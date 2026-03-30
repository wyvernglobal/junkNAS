package daemon

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
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
	watchdogInterval   = 30 * time.Second
	heartbeatInterval  = 60 * time.Second
	smbPort            = 445
	peerMountBase      = "/mnt/junknas-peers"
	socks5ReadyTimeout = 3 * time.Minute

	// apiListenAddr must match api/server.go's hardcoded listen address.
	// The port is also registered with i2p.New so the api-server tunnel
	// forwards I2P connections to the correct local port.
	apiListenAddr = "127.0.0.1:36789"
	apiPort       = 36789
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

	// Create the I2P manager with the API port so that the api-server tunnel
	// in tunnels.conf forwards to the correct local port.
	i2pMgr, err := i2p.New("/var/lib/i2pd", smbPort, apiPort)
	if err != nil {
		return nil, fmt.Errorf("daemon: i2p: %w", err)
	}

	var smbMgr *smb.Manager
	role := registry.RoleLeech
	if cfg.StoragePath != "" {
		role = registry.RoleStorage
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
	log.Println("[daemon] i2pd started — waiting for SOCKS5 proxy...")

	ctx, cancel := context.WithTimeout(context.Background(), socks5ReadyTimeout)
	defer cancel()
	if err := i2p.WaitForSOCKS5(ctx); err != nil {
		return fmt.Errorf("daemon: SOCKS5 never came up: %w", err)
	}
	log.Printf("[daemon] SOCKS5 ready on %s", i2p.SOCKS5Addr)

	d.proto.SetHTTPClient(i2p.NewHTTPClient())

	// Update self with the B32 addresses now that i2pd has generated the keys.
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

	// Keep retrying until both B32 addresses are resolved.
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

func (d *Daemon) onTopologyChange() {
	log.Println("[daemon] topology changed — rebuilding")
	if err := d.rebuildTunnels(); err != nil {
		log.Printf("[daemon] tunnel rebuild: %v", err)
	}
	time.Sleep(3 * time.Second)
	if err := d.mountNewPeers(); err != nil {
		log.Printf("[daemon] peer mount: %v", err)
	}
	if err := d.rebuildMergerfs(); err != nil {
		log.Printf("[daemon] mergerfs rebuild: %v", err)
	}
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

// retryB32 keeps polling the i2pd keyfiles until both SMB and API B32
// addresses are available and persisted to the registry.
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
			continue // still waiting
		}

		self := d.reg.Self()
		if self == nil {
			continue
		}
		if self.B32 == apiB32 && self.SMBB32 == smbB32 {
			return // both already up to date
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

// bootstrapSelf creates the initial self record. B32 addresses are not yet
// known (i2pd hasn't started); they are filled in by Start() and retryB32().
func (d *Daemon) bootstrapSelf(role registry.Role) error {
	phrase, err := words.Generate()
	if err != nil {
		return fmt.Errorf("generate phrase: %w", err)
	}
	return d.reg.SetSelf(&registry.Self{
		B32:         "pending", // API B32 — set by Start() once i2pd is ready
		SMBB32:      "pending", // SMB B32 — set by Start() once i2pd is ready
		Phrase:      phrase,
		PhraseHash:  phrase.Hash(),
		Role:        role,
		QuotaBytes:  d.cfg.QuotaBytes,
		StoragePath: d.cfg.StoragePath,
		JoinedAt:    time.Now(),
	})
}

// rebuildTunnels rewrites tunnels.conf using each peer's SMB B32 address
// (not the API B32) as the I2P client tunnel destination.
func (d *Daemon) rebuildTunnels() error {
	peers := d.reg.Peers()
	tPeers := make([]i2p.TunnelPeer, 0, len(peers))
	for _, p := range peers {
		// Use SMBB32 for the SMB client tunnel. Fall back to B32 if SMBB32
		// is empty (e.g. older peer records that predate the split).
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

func (d *Daemon) mountNewPeers() error {
	for _, p := range d.reg.Peers() {
		mountPath := peerMountBase + "/" + p.Phrase[0] + "-" + p.Phrase[1] + "-" + p.Phrase[2]
		if _, err := os.Stat(mountPath); err == nil {
			continue
		}
		if _, err := mergerfs.MountPeer(p, peerMountBase, d.cfg.SambaUser, d.cfg.SambaPass); err != nil {
			log.Printf("[daemon] mount peer %q: %v", p.Identity(), err)
		}
	}
	return nil
}

func (d *Daemon) rebuildMergerfs() error {
	peers := d.reg.StoragePeers()
	mounts := make([]*mergerfs.PeerMount, 0, len(peers))
	for _, p := range peers {
		mounts = append(mounts, &mergerfs.PeerMount{
			B32:       p.B32,
			MountPath: peerMountBase + "/" + p.Phrase[0] + "-" + p.Phrase[1] + "-" + p.Phrase[2],
			Storage:   true,
		})
	}
	selfPath := ""
	if s := d.reg.Self(); s != nil && s.Role == registry.RoleStorage {
		selfPath = s.StoragePath
	}
	return d.mergeMgr.Rebuild(mounts, selfPath)
}
