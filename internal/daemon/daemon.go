package daemon

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/junknas/junknas/internal/api"
	"github.com/junknas/junknas/internal/i2p"
	"github.com/junknas/junknas/internal/join"
	"github.com/junknas/junknas/internal/mergerfs"
	"github.com/junknas/junknas/internal/registry"
	"github.com/junknas/junknas/internal/smb"
	"github.com/junknas/junknas/internal/words"
)

const (
	watchdogInterval  = 30 * time.Second
	heartbeatInterval = 60 * time.Second
	smbPort           = 445
	peerMountBase     = "/mnt/junknas-peers"
	proxyReadyTimeout = 3 * time.Minute

	apiListenAddr = "127.0.0.1:6767"
	apiPort       = 6767

	// How long to wait after reloading i2pd tunnels before attempting CIFS mounts.
	// I2P needs time to negotiate the new tunnel even after the config reload.
	tunnelEstablishWait = 20 * time.Second
	// How many times to retry a CIFS mount before giving up.
	mountRetries = 3
	// Delay between mount retries.
	mountRetryDelay = 20 * time.Second
)

type Config struct {
	DataDir     string
	StoragePath string
	QuotaBytes  int64
	SambaUser   string
	SambaPass   string
}

type Daemon struct {
	cfg      Config
	reg      *registry.Registry
	i2pMgr   *i2p.Manager
	smbMgr   *smb.Manager
	mergeMgr *mergerfs.Manager
	apiSrv   *api.Server
	proto    *join.Protocol
	stopCh   chan struct{}
}

func New(cfg Config) (*Daemon, error) {
	for _, dir := range []string{cfg.DataDir, peerMountBase} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("daemon: mkdir %s: %w", dir, err)
		}
	}

	reg, err := registry.New(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("daemon: registry: %w", err)
	}

	i2pMgr, err := i2p.New("/var/lib/i2pd", smbPort, apiPort)
	if err != nil {
		return nil, fmt.Errorf("daemon: i2p: %w", err)
	}

	var smbMgr *smb.Manager
	role := registry.RoleLeech
	if cfg.StoragePath != "" {
		role = registry.RoleStorage
		// Ensure the storage directory exists before starting Samba.
		if err := os.MkdirAll(cfg.StoragePath, 0o750); err != nil {
			return nil, fmt.Errorf("daemon: mkdir storage %s: %w", cfg.StoragePath, err)
		}
		smbMgr, err = smb.New(smb.Config{
			StoragePath: cfg.StoragePath,
			QuotaBytes:  cfg.QuotaBytes,
			SambaUser:   cfg.SambaUser,
			SambaPass:   cfg.SambaPass,
			ConfDir:     filepath.Join(cfg.DataDir, "smb"),
		})
		if err != nil {
			return nil, fmt.Errorf("daemon: smb: %w", err)
		}
	}

	mergeMgr, err := mergerfs.New()
	if err != nil {
		return nil, fmt.Errorf("daemon: mergerfs: %w", err)
	}

	proto := join.New(reg)

	d := &Daemon{
		cfg:      cfg,
		reg:      reg,
		i2pMgr:   i2pMgr,
		smbMgr:   smbMgr,
		mergeMgr: mergeMgr,
		proto:    proto,
		stopCh:   make(chan struct{}),
	}

	apiSrv, err := api.New(reg, proto, i2pMgr, d.onTopologyChange)
	if err != nil {
		return nil, fmt.Errorf("daemon: api: %w", err)
	}
	d.apiSrv = apiSrv

	if reg.Self() == nil {
		if err := d.bootstrapSelf(role); err != nil {
			return nil, fmt.Errorf("daemon: bootstrap: %w", err)
		}
	}
	return d, nil
}

func (d *Daemon) Start() error {
	log.Println("[daemon] Starting JunkNAS...")

	if err := d.i2pMgr.Start(); err != nil {
		return fmt.Errorf("daemon: i2p start: %w", err)
	}
	log.Println("[daemon] i2pd started — waiting for proxy...")

	ctx, cancel := context.WithTimeout(context.Background(), proxyReadyTimeout)
	defer cancel()
	if err := d.i2pMgr.WaitForProxy(ctx); err != nil {
		return fmt.Errorf("daemon: proxy never came up: %w", err)
	}
	log.Printf("[daemon] proxy ready on %s", d.i2pMgr.ProxAddr)

	d.proto.SetHTTPClient(d.i2pMgr.NewHTTPClient())

	apiB32 := d.i2pMgr.APIAddress()
	smbB32 := d.i2pMgr.SMBAddress()
	if apiB32 != "" {
		log.Printf("[daemon] API B32: %s", apiB32)
	}
	if smbB32 != "" {
		log.Printf("[daemon] SMB B32: %s", smbB32)
	}

	if self := d.reg.Self(); self != nil {
		updated := false
		if apiB32 != "" && self.B32 != apiB32 {
			self.B32 = apiB32
			updated = true
		}
		if smbB32 != "" && self.SMBB32 != smbB32 {
			self.SMBB32 = smbB32
			updated = true
		}
		if updated {
			_ = d.reg.SetSelf(self)
		}
	}

	go d.retryB32()

	if d.smbMgr != nil {
		if err := d.smbMgr.Start(); err != nil {
			return fmt.Errorf("daemon: smb start: %w", err)
		}
		log.Println("[daemon] Samba running on 127.0.0.1:445")
	}

	if err := d.apiSrv.WriteLockFile(); err != nil {
		log.Printf("[daemon] warn: lock file: %v", err)
	}
	log.Println("[daemon] Created lockfile")

	if err := d.rebuildTunnels(); err != nil {
		log.Printf("[daemon] warn: initial tunnel rebuild: %v", err)
	}
	if err := d.rebuildMergerfs(); err != nil {
		log.Printf("[daemon] warn: initial mergerfs: %v", err)
	}

	go d.watchdog()
	go d.heartbeat()

	log.Printf("[daemon] API on %s", apiListenAddr)
	return d.apiSrv.Serve()
}

func (d *Daemon) Stop() {
	close(d.stopCh)
	if d.mergeMgr.IsMounted() {
		_ = d.mergeMgr.Unmount()
	}
	if d.smbMgr != nil {
		d.smbMgr.Stop()
	}
	d.i2pMgr.Stop()
}

// onTopologyChange is called whenever a peer joins or is announced.
// It starts SMB if we've become a storage node, rebuilds I2P tunnels,
// then asynchronously waits for tunnels to establish before mounting peers
// and rebuilding the mergerfs union.
func (d *Daemon) onTopologyChange() {
	log.Println("[daemon] topology changed — rebuilding")

	// If this node is now a storage node but SMB isn't running yet
	// (e.g. we just completed a join with --storage), start it now.
	if self := d.reg.Self(); self != nil && self.Role == registry.RoleStorage && d.smbMgr == nil && self.StoragePath != "" {
		log.Printf("[daemon] storage node with no SMB manager — starting Samba for %s", self.StoragePath)
		if err := os.MkdirAll(self.StoragePath, 0o750); err != nil {
			log.Printf("[daemon] mkdir storage %s: %v", self.StoragePath, err)
		}
		mgr, err := smb.New(smb.Config{
			StoragePath: self.StoragePath,
			QuotaBytes:  self.QuotaBytes,
			SambaUser:   d.cfg.SambaUser,
			SambaPass:   d.cfg.SambaPass,
			ConfDir:     filepath.Join(d.cfg.DataDir, "smb"),
		})
		if err != nil {
			log.Printf("[daemon] smb init: %v", err)
		} else if err := mgr.Start(); err != nil {
			log.Printf("[daemon] smb start: %v", err)
		} else {
			d.smbMgr = mgr
			log.Println("[daemon] Samba started after role upgrade to storage")
		}
	}

	// Rewrite tunnels.conf and signal i2pd to reload.
	if err := d.rebuildTunnels(); err != nil {
		log.Printf("[daemon] tunnel rebuild: %v", err)
	}

	// Mount new peers and rebuild mergerfs in the background.
	// I2P needs time to negotiate tunnels after the reload signal, so we
	// wait before attempting CIFS mounts.
	go func() {
		log.Printf("[daemon] waiting %s for I2P tunnels to establish...", tunnelEstablishWait)
		time.Sleep(tunnelEstablishWait)
		if err := d.mountNewPeers(); err != nil {
			log.Printf("[daemon] peer mount: %v", err)
		}
		if err := d.rebuildMergerfs(); err != nil {
			log.Printf("[daemon] mergerfs rebuild: %v", err)
		}
	}()
}

func (d *Daemon) watchdog() {
	t := time.NewTicker(watchdogInterval)
	defer t.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case <-t.C:
			if d.smbMgr != nil {
				if err := d.smbMgr.CheckAndEnforceQuota(); err != nil {
					log.Printf("[watchdog] quota: %v", err)
				}
			}
			d.checkPeerHealth()
		}
	}
}

func (d *Daemon) heartbeat() {
	t := time.NewTicker(heartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case <-t.C:
			d.pingAllPeers()
		}
	}
}

func (d *Daemon) retryB32() {
	for {
		select {
		case <-d.stopCh:
			return
		case <-time.After(15 * time.Second):
		}

		apiB32 := d.i2pMgr.APIAddress()
		smbB32 := d.i2pMgr.SMBAddress()

		if apiB32 == "" {
			continue
		}

		self := d.reg.Self()
		if self == nil {
			continue
		}
		if self.B32 == apiB32 && self.SMBB32 == smbB32 {
			return
		}

		self.B32 = apiB32
		if smbB32 != "" {
			self.SMBB32 = smbB32
		}
		if err := d.reg.SetSelf(self); err != nil {
			log.Printf("[daemon] retryB32: persist: %v", err)
		} else {
			log.Printf("[daemon] B32 resolved — API: %s  SMB: %s", apiB32, smbB32)
			return
		}
	}
}

func (d *Daemon) checkPeerHealth() {
	needRebuild := false
	for _, p := range d.reg.Peers() {
		healthy := d.dialPeer(p)
		desired := registry.StatusHealthy
		if !healthy {
			desired = registry.StatusUnreachable
		}
		if p.Status != desired {
			_ = d.reg.UpdatePeerStatus(p.B32, desired)
			if !healthy {
				log.Printf("[watchdog] peer %q unreachable — remounting", p.Identity())
				d.remountPeer(p)
			}
			needRebuild = true
		}
	}
	if needRebuild {
		_ = d.rebuildMergerfs()
	}
}

func (d *Daemon) pingAllPeers() {
	for _, p := range d.reg.Peers() {
		if d.dialPeer(p) {
			_ = d.reg.UpdatePeerStatus(p.B32, registry.StatusHealthy)
		}
	}
}

func (d *Daemon) dialPeer(p *registry.Peer) bool {
	conn, err := net.DialTimeout("tcp",
		fmt.Sprintf("127.0.0.1:%d", p.LocalMountPort), 5*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (d *Daemon) remountPeer(p *registry.Peer) {
	_ = mergerfs.UnmountPeer(p, peerMountBase)
	time.Sleep(5 * time.Second)
	if _, err := mergerfs.MountPeer(p, peerMountBase, d.cfg.SambaUser, d.cfg.SambaPass); err != nil {
		log.Printf("[watchdog] remount %q: %v", p.Identity(), err)
	}
}

func (d *Daemon) bootstrapSelf(role registry.Role) error {
	phrase, err := words.Generate()
	if err != nil {
		return fmt.Errorf("generate phrase: %w", err)
	}
	return d.reg.SetSelf(&registry.Self{
		B32:         "pending",
		SMBB32:      "pending",
		Phrase:      phrase,
		PhraseHash:  phrase.Hash(),
		Role:        role,
		QuotaBytes:  d.cfg.QuotaBytes,
		StoragePath: d.cfg.StoragePath,
		JoinedAt:    time.Now(),
	})
}

func (d *Daemon) rebuildTunnels() error {
	peers := d.reg.Peers()
	tPeers := make([]i2p.TunnelPeer, 0, len(peers))
	for _, p := range peers {
		smbDest := p.SMBB32
		if smbDest == "" || smbDest == "pending" {
			smbDest = p.B32
		}
		tPeers = append(tPeers, i2p.TunnelPeer{
			Identity:  p.Identity(),
			B32:       smbDest,
			LocalPort: p.LocalMountPort,
		})
	}
	return d.i2pMgr.ReloadTunnels(smbPort, tPeers)
}

// isMounted reports whether path appears in /proc/mounts as an active mount.
func isMounted(path string) bool {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false
	}
	// Each line: device mountpoint fstype options dump pass
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == path {
			return true
		}
	}
	return false
}

// mountNewPeers mounts any peer whose mount path is not currently active.
// Each mount is retried up to mountRetries times with mountRetryDelay between
// attempts, because I2P tunnels may still be negotiating.
func (d *Daemon) mountNewPeers() error {
	for _, p := range d.reg.Peers() {
		mountPath := peerMountBase + "/" + p.Phrase[0] + "-" + p.Phrase[1] + "-" + p.Phrase[2]

		if isMounted(mountPath) {
			continue
		}

		var lastErr error
		for attempt := 1; attempt <= mountRetries; attempt++ {
			if attempt > 1 {
				log.Printf("[daemon] mount peer %q: retry %d/%d in %s",
					p.Identity(), attempt, mountRetries, mountRetryDelay)
				time.Sleep(mountRetryDelay)
			}
			if _, err := mergerfs.MountPeer(p, peerMountBase, d.cfg.SambaUser, d.cfg.SambaPass); err != nil {
				lastErr = err
				log.Printf("[daemon] mount peer %q (attempt %d/%d): %v",
					p.Identity(), attempt, mountRetries, err)
				continue
			}
			lastErr = nil
			log.Printf("[daemon] mounted peer %q at %s", p.Identity(), mountPath)
			break
		}
		if lastErr != nil {
			log.Printf("[daemon] mount peer %q failed after %d attempts: %v",
				p.Identity(), mountRetries, lastErr)
		}
	}
	return nil
}

func (d *Daemon) rebuildMergerfs() error {
	peers := d.reg.StoragePeers()
	mounts := make([]*mergerfs.PeerMount, 0, len(peers))
	for _, p := range peers {
		mountPath := peerMountBase + "/" + p.Phrase[0] + "-" + p.Phrase[1] + "-" + p.Phrase[2]
		// Only include peers whose CIFS mount is actually active.
		if !isMounted(mountPath) {
			log.Printf("[daemon] skipping peer %q in mergerfs — not yet mounted", p.Identity())
			continue
		}
		mounts = append(mounts, &mergerfs.PeerMount{
			B32:       p.B32,
			MountPath: mountPath,
			Storage:   true,
		})
	}
	selfPath := ""
	if s := d.reg.Self(); s != nil && s.Role == registry.RoleStorage {
		selfPath = s.StoragePath
	}
	return d.mergeMgr.Rebuild(mounts, selfPath)
}

// UpdateSelf updates the local self record with new quota and storage path.
// If the role changes to storage and smbMgr is not running, it will be started.
func (d *Daemon) UpdateSelf(quotaBytes int64, storagePath string) error {
	self := d.reg.Self()
	if self == nil {
		return fmt.Errorf("daemon: self not initialized")
	}
	updated := false
	if quotaBytes > 0 && self.QuotaBytes != quotaBytes {
		self.QuotaBytes = quotaBytes
		updated = true
	}
	if storagePath != "" && self.StoragePath != storagePath {
		self.StoragePath = storagePath
		updated = true
	}
	if updated {
		if err := d.reg.SetSelf(self); err != nil {
			return err
		}
	}
	// If we are now a storage node and the smb manager isn't running, start it.
	if self.Role == registry.RoleStorage && d.smbMgr == nil && self.StoragePath != "" {
		if err := os.MkdirAll(self.StoragePath, 0o750); err != nil {
			return fmt.Errorf("daemon: mkdir storage: %w", err)
		}
		var err error
		d.smbMgr, err = smb.New(smb.Config{
			StoragePath: self.StoragePath,
			QuotaBytes:  self.QuotaBytes,
			SambaUser:   d.cfg.SambaUser,
			SambaPass:   d.cfg.SambaPass,
			ConfDir:     filepath.Join(d.cfg.DataDir, "smb"),
		})
		if err != nil {
			return fmt.Errorf("daemon: smb start: %w", err)
		}
		if err := d.smbMgr.Start(); err != nil {
			return fmt.Errorf("daemon: smb start: %w", err)
		}
		log.Println("[daemon] Samba started after role upgrade")
	} else if d.smbMgr != nil && self.Role == registry.RoleStorage && self.QuotaBytes != d.smbMgr.Cfg().QuotaBytes {
		// Update quota in smb manager if it changed
		d.smbMgr.UpdateQuota(self.QuotaBytes)
	}
	return nil
}
