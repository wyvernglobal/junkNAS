package daemon

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"junknas/internal/i2p"
	"junknas/internal/storage"
	"junknas/internal/words"
)

const (
	watchdogInterval  = 30 * time.Second
	heartbeatInterval = 60 * time.Second
	smbPort           = 445
	proxyReadyTimeout = 3 * time.Minute

	apiListenAddr = "127.0.0.1:6767"
	apiPort       = 6767

	tunnelEstablishWait = 20 * time.Second
	mountRetries        = 3
	mountRetryDelay     = 20 * time.Second
)

type Config struct {
	DataDir     string
	StoragePath string
	QuotaBytes  int64
	SambaUser   string
	SambaPass   string
}

type Daemon struct {
	cfg     Config
	reg     *Registry
	i2pMgr  *i2p.Manager
	storage *storage.Manager
	apiSrv  *apiServer
	Proto   *Protocol
	stopCh  chan struct{}
}

func New(cfg Config) (*Daemon, error) {
	for _, dir := range []string{cfg.DataDir, storage.PeerMountBase} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("daemon: mkdir %s: %w", dir, err)
		}
	}

	reg, err := NewRegistry(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("daemon: registry: %w", err)
	}

	i2pMgr, err := i2p.New("/var/lib/i2pd", smbPort, apiPort)
	if err != nil {
		return nil, fmt.Errorf("daemon: i2p: %w", err)
	}

	storageCfg := storage.Config{}
	role := RoleLeech
	if cfg.StoragePath != "" {
		role = RoleStorage
		storageCfg = storage.Config{
			StoragePath: cfg.StoragePath,
			QuotaBytes:  cfg.QuotaBytes,
			SambaUser:   cfg.SambaUser,
			SambaPass:   cfg.SambaPass,
			ConfDir:     filepath.Join(cfg.DataDir, "smb"),
		}
	}
	storeMgr, err := storage.New(storageCfg)
	if err != nil {
		return nil, fmt.Errorf("daemon: storage: %w", err)
	}

	proto := NewProtocol(reg)

	d := &Daemon{
		cfg:     cfg,
		reg:     reg,
		i2pMgr:  i2pMgr,
		storage: storeMgr,
		Proto:   proto,
		stopCh:  make(chan struct{}),
	}
	d.apiSrv = newAPIServer(d)

	if reg.Self() == nil {
		if err := d.bootstrapSelf(role); err != nil {
			return nil, fmt.Errorf("daemon: bootstrap: %w", err)
		}
	}
	return d, nil
}

func (d *Daemon) Registry() *Registry        { return d.reg }
func (d *Daemon) Storage() *storage.Manager  { return d.storage }
func (d *Daemon) I2P() *i2p.Manager          { return d.i2pMgr }

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

	d.Proto.SetHTTPClient(d.i2pMgr.NewHTTPClient())

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

	if d.storage.HasSMB() {
		if err := d.storage.StartSMB(); err != nil {
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
	if err := d.rebuildUnion(); err != nil {
		log.Printf("[daemon] warn: initial union rebuild: %v", err)
	}

	go d.watchdog()
	go d.heartbeat()

	log.Printf("[daemon] API on %s", apiListenAddr)
	return d.apiSrv.Serve()
}

func (d *Daemon) Stop() {
	close(d.stopCh)
	if d.storage.IsMounted() {
		_ = d.storage.Unmount()
	}
	d.storage.StopSMB()
	d.i2pMgr.Stop()
}

func (d *Daemon) onTopologyChange() {
	log.Println("[daemon] topology changed — rebuilding")

	if self := d.reg.Self(); self != nil && self.Role == RoleStorage && !d.storage.HasSMB() && self.StoragePath != "" {
		log.Printf("[daemon] storage node with no SMB — starting Samba for %s", self.StoragePath)
		err := d.storage.EnableSMB(storage.Config{
			StoragePath: self.StoragePath,
			QuotaBytes:  self.QuotaBytes,
			SambaUser:   d.cfg.SambaUser,
			SambaPass:   d.cfg.SambaPass,
			ConfDir:     filepath.Join(d.cfg.DataDir, "smb"),
		})
		if err != nil {
			log.Printf("[daemon] smb enable: %v", err)
		} else if err := d.storage.StartSMB(); err != nil {
			log.Printf("[daemon] smb start: %v", err)
		} else {
			log.Println("[daemon] Samba started after role upgrade to storage")
		}
	}

	if err := d.rebuildTunnels(); err != nil {
		log.Printf("[daemon] tunnel rebuild: %v", err)
	}

	go func() {
		log.Printf("[daemon] waiting %s for I2P tunnels to establish...", tunnelEstablishWait)
		time.Sleep(tunnelEstablishWait)
		if err := d.mountNewPeers(); err != nil {
			log.Printf("[daemon] peer mount: %v", err)
		}
		if err := d.rebuildUnion(); err != nil {
			log.Printf("[daemon] union rebuild: %v", err)
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
			if d.storage.HasSMB() {
				if err := d.storage.CheckAndEnforceQuota(); err != nil {
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
		desired := StatusHealthy
		if !healthy {
			desired = StatusUnreachable
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
		_ = d.rebuildUnion()
	}
}

func (d *Daemon) pingAllPeers() {
	for _, p := range d.reg.Peers() {
		if d.dialPeer(p) {
			_ = d.reg.UpdatePeerStatus(p.B32, StatusHealthy)
		}
	}
}

func (d *Daemon) dialPeer(p *Peer) bool {
	conn, err := net.DialTimeout("tcp",
		fmt.Sprintf("127.0.0.1:%d", p.LocalMountPort), 5*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (d *Daemon) remountPeer(p *Peer) {
	_ = storage.UnmountPeer(p.DirName())
	time.Sleep(5 * time.Second)
	if _, err := storage.MountPeer(p.DirName(), p.LocalMountPort, d.cfg.SambaUser, d.cfg.SambaPass); err != nil {
		log.Printf("[watchdog] remount %q: %v", p.Identity(), err)
	}
}

func (d *Daemon) bootstrapSelf(role Role) error {
	phrase, err := words.Generate()
	if err != nil {
		return fmt.Errorf("generate phrase: %w", err)
	}
	return d.reg.SetSelf(&Self{
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

func (d *Daemon) mountNewPeers() error {
	for _, p := range d.reg.Peers() {
		mountPath := storage.PeerMountPath(p.DirName())
		if storage.IsPathMounted(mountPath) {
			continue
		}

		var lastErr error
		for attempt := 1; attempt <= mountRetries; attempt++ {
			if attempt > 1 {
				log.Printf("[daemon] mount peer %q: retry %d/%d in %s",
					p.Identity(), attempt, mountRetries, mountRetryDelay)
				time.Sleep(mountRetryDelay)
			}
			if _, err := storage.MountPeer(p.DirName(), p.LocalMountPort, d.cfg.SambaUser, d.cfg.SambaPass); err != nil {
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

func (d *Daemon) rebuildUnion() error {
	peers := d.reg.StoragePeers()
	branches := make([]storage.Branch, 0, len(peers))
	for _, p := range peers {
		mountPath := storage.PeerMountPath(p.DirName())
		if !storage.IsPathMounted(mountPath) {
			log.Printf("[daemon] skipping peer %q in union — not yet mounted", p.Identity())
			continue
		}
		branches = append(branches, storage.Branch{
			Name: p.DirName(),
			Path: mountPath,
		})
	}
	selfPath := ""
	if s := d.reg.Self(); s != nil && s.Role == RoleStorage {
		selfPath = s.StoragePath
	}
	return d.storage.Rebuild(branches, selfPath)
}

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
	if self.Role == RoleStorage && !d.storage.HasSMB() && self.StoragePath != "" {
		err := d.storage.EnableSMB(storage.Config{
			StoragePath: self.StoragePath,
			QuotaBytes:  self.QuotaBytes,
			SambaUser:   d.cfg.SambaUser,
			SambaPass:   d.cfg.SambaPass,
			ConfDir:     filepath.Join(d.cfg.DataDir, "smb"),
		})
		if err != nil {
			return fmt.Errorf("daemon: smb enable: %w", err)
		}
		if err := d.storage.StartSMB(); err != nil {
			return fmt.Errorf("daemon: smb start: %w", err)
		}
		log.Println("[daemon] Samba started after role upgrade")
	} else if d.storage.HasSMB() && self.Role == RoleStorage && self.QuotaBytes != d.storage.Cfg().QuotaBytes {
		d.storage.UpdateQuota(self.QuotaBytes)
	}
	return nil
}
