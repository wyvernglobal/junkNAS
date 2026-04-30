// Package storage owns everything that puts bytes on disk for JunkNAS:
//
//   - Samba (smbd) — exposes the local vault to peers over I2P-tunnelled CIFS
//   - peer CIFS mounts — pulls each peer's vault to /mnt/junknas-peers/<id>
//   - the unified view — assembled at /mnt/junknas
//
// The unified view is normally a mergerfs (FUSE) union. mergerfs needs
// /dev/fuse, which is unavailable in unprivileged containers. When FUSE is
// unreachable the manager falls back to a "virtual union": /mnt/junknas is a
// plain directory containing one symlink per branch (self + each peer mount).
// Reads work through the symlinks; writes go to whichever branch the caller
// chose. It's not a true union, but it requires no kernel features and keeps
// the cloud browseable in Docker.
package storage

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"text/template"
)

const (
	MountPoint    = "/mnt/junknas"
	PeerMountBase = "/mnt/junknas-peers"
	FuseDevice    = "/dev/fuse"
)

type Branch struct {
	Name string
	Path string
}

type Config struct {
	StoragePath string
	QuotaBytes  int64
	SambaUser   string
	SambaPass   string
	ConfDir     string
}

type Manager struct {
	cfg      Config
	confPath string
	smbCmd   *exec.Cmd
	readOnly bool

	mountPoint    string
	useFuse       bool
	mergerMounted bool
	virtualLinks  map[string]string
}

func New(cfg Config) (*Manager, error) {
	if err := os.MkdirAll(MountPoint, 0o755); err != nil {
		return nil, fmt.Errorf("storage: mkdir %s: %w", MountPoint, err)
	}
	if err := os.MkdirAll(PeerMountBase, 0o755); err != nil {
		return nil, fmt.Errorf("storage: mkdir %s: %w", PeerMountBase, err)
	}

	m := &Manager{
		cfg:          cfg,
		mountPoint:   MountPoint,
		useFuse:      probeFuse(),
		virtualLinks: make(map[string]string),
	}
	if cfg.ConfDir != "" {
		m.confPath = filepath.Join(cfg.ConfDir, "smb.conf")
		if err := os.MkdirAll(cfg.ConfDir, 0o700); err != nil {
			return nil, fmt.Errorf("storage: mkdir conf: %w", err)
		}
	}
	if cfg.StoragePath != "" {
		if err := os.MkdirAll(cfg.StoragePath, 0o750); err != nil {
			return nil, fmt.Errorf("storage: mkdir storage: %w", err)
		}
	}
	if !m.useFuse {
		log.Printf("[storage] %s unavailable — using virtual-union fallback (no mergerfs)", FuseDevice)
	}
	return m, nil
}

func (m *Manager) FuseAvailable() bool { return m.useFuse }
func (m *Manager) MountPoint() string  { return m.mountPoint }

func (m *Manager) IsMounted() bool {
	if m.useFuse {
		return m.mergerMounted
	}
	return len(m.virtualLinks) > 0
}

func probeFuse() bool {
	f, err := os.OpenFile(FuseDevice, os.O_RDWR, 0)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

func IsPathMounted(path string) bool {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == path {
			return true
		}
	}
	return false
}

func (m *Manager) Rebuild(branches []Branch, selfStoragePath string) error {
	all := make([]Branch, 0, len(branches)+1)
	if selfStoragePath != "" {
		all = append(all, Branch{Name: "self", Path: selfStoragePath})
	}
	all = append(all, branches...)

	if m.useFuse {
		return m.rebuildMergerfs(all)
	}
	return m.rebuildVirtual(all)
}

func (m *Manager) rebuildMergerfs(branches []Branch) error {
	if m.mergerMounted {
		if err := m.unmountMergerfs(); err != nil {
			return err
		}
	}
	if len(branches) == 0 {
		return nil
	}
	paths := make([]string, 0, len(branches))
	for _, b := range branches {
		paths = append(paths, b.Path)
	}
	branchStr := strings.Join(paths, ":")
	args := []string{
		branchStr,
		m.mountPoint,
		"-o",
		strings.Join([]string{
			"func.create=mfs",
			"cache.files=partial",
			"dropcacheonclose=true",
			"category.search=ff",
			"minfreespace=1G",
			"fsname=junknas",
			"allow_other",
		}, ","),
	}
	cmd := exec.Command("mergerfs", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("storage: mergerfs mount: %w", err)
	}
	m.mergerMounted = true
	return nil
}

func (m *Manager) unmountMergerfs() error {
	cmd := exec.Command("fusermount", "-u", m.mountPoint)
	if err := cmd.Run(); err != nil {
		cmd2 := exec.Command("fusermount", "-uz", m.mountPoint)
		if err2 := cmd2.Run(); err2 != nil {
			return fmt.Errorf("storage: unmount: %w (lazy: %v)", err, err2)
		}
	}
	m.mergerMounted = false
	return nil
}

func (m *Manager) rebuildVirtual(branches []Branch) error {
	desired := make(map[string]string, len(branches))
	for _, b := range branches {
		if b.Name == "" || b.Path == "" {
			continue
		}
		desired[b.Name] = b.Path
	}
	for name := range m.virtualLinks {
		if _, ok := desired[name]; ok {
			continue
		}
		_ = os.Remove(filepath.Join(m.mountPoint, name))
		delete(m.virtualLinks, name)
	}
	for name, target := range desired {
		linkPath := filepath.Join(m.mountPoint, name)
		if existing, err := os.Readlink(linkPath); err == nil && existing == target {
			m.virtualLinks[name] = target
			continue
		}
		_ = os.Remove(linkPath)
		if err := os.Symlink(target, linkPath); err != nil {
			return fmt.Errorf("storage: virtual link %s -> %s: %w", linkPath, target, err)
		}
		m.virtualLinks[name] = target
	}
	return nil
}

func (m *Manager) Unmount() error {
	if m.useFuse {
		if !m.mergerMounted {
			return nil
		}
		return m.unmountMergerfs()
	}
	for name := range m.virtualLinks {
		_ = os.Remove(filepath.Join(m.mountPoint, name))
	}
	m.virtualLinks = make(map[string]string)
	return nil
}

func PeerMountPath(name string) string {
	return filepath.Join(PeerMountBase, name)
}

func MountPeer(name string, localPort int, user, pass string) (string, error) {
	mountPath := PeerMountPath(name)
	if err := os.MkdirAll(mountPath, 0o755); err != nil {
		return "", fmt.Errorf("storage: peer mkdir %s: %w", mountPath, err)
	}
	addr := "//127.0.0.1/vault"
	opts := fmt.Sprintf(
		"port=%d,username=%s,password=%s,vers=3.0,seal,iocharset=utf8",
		localPort, user, pass,
	)
	cmd := exec.Command("mount", "-t", "cifs", addr, mountPath, "-o", opts)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("storage: mount peer %s: %w — %s", name, err, out)
	}
	return mountPath, nil
}

func UnmountPeer(name string) error {
	mountPath := PeerMountPath(name)
	cmd := exec.Command("umount", mountPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("storage: umount peer %s: %w — %s", name, err, out)
	}
	return nil
}

const smbConfTmpl = `# JunkNAS Samba configuration — auto-generated. Do not edit.
[global]
	workgroup = JUNKNAS
	server string = JunkNAS Node
	netbios name = JUNKNAS

	interfaces = 127.0.0.1
	bind interfaces only = yes

	server min protocol = SMB3
	smb encrypt = required

	log level = 1
	log file = {{.LogFile}}
	max log size = 10240

	security = user
	map to guest = never
	restrict anonymous = 2

	socket options = TCP_NODELAY SO_RCVBUF=131072 SO_SNDBUF=131072
	read raw = yes
	write raw = yes
	max xmit = 65535
	dead time = 15
	getwd cache = yes

[vault]
	comment = JunkNAS Vault
	path = {{.StoragePath}}
	valid users = {{.SambaUser}}
	read only = {{.ReadOnly}}
	browseable = no
	writable = {{.Writable}}
	create mask = 0660
	directory mask = 0770
	force create mode = 0660
	force directory mode = 0770
`

func (m *Manager) HasSMB() bool   { return m.cfg.StoragePath != "" && m.confPath != "" }
func (m *Manager) Cfg() Config    { return m.cfg }
func (m *Manager) ConfPath() string { return m.confPath }

func (m *Manager) UsedBytes() (int64, error) {
	if m.cfg.StoragePath == "" {
		return 0, nil
	}
	out, err := exec.Command("du", "-sb", m.cfg.StoragePath).Output()
	if err != nil {
		return 0, fmt.Errorf("storage: du: %w", err)
	}
	var used int64
	fmt.Sscanf(string(out), "%d", &used)
	return used, nil
}

func (m *Manager) FreeBytes() (int64, error) {
	if m.cfg.StoragePath == "" {
		return 0, nil
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(m.cfg.StoragePath, &st); err != nil {
		return 0, fmt.Errorf("storage: statfs: %w", err)
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}

func (m *Manager) QuotaExceeded() bool {
	if m.cfg.QuotaBytes <= 0 {
		return false
	}
	used, err := m.UsedBytes()
	if err != nil {
		return false
	}
	return used >= m.cfg.QuotaBytes
}

func (m *Manager) QuotaRemaining() int64 {
	if m.cfg.QuotaBytes <= 0 {
		return -1
	}
	used, err := m.UsedBytes()
	if err != nil {
		return m.cfg.QuotaBytes
	}
	rem := m.cfg.QuotaBytes - used
	if rem < 0 {
		return 0
	}
	return rem
}

func (m *Manager) CheckAndEnforceQuota() error {
	if !m.HasSMB() {
		return nil
	}
	exceeded := m.QuotaExceeded()
	if exceeded == m.readOnly {
		return nil
	}
	m.readOnly = exceeded
	return m.Reload()
}

func (m *Manager) writeSMBConfig() error {
	tmpl, err := template.New("smb").Parse(smbConfTmpl)
	if err != nil {
		return fmt.Errorf("storage: template parse: %w", err)
	}
	type data struct {
		StoragePath string
		SambaUser   string
		LogFile     string
		ReadOnly    string
		Writable    string
	}
	readOnly := "no"
	writable := "yes"
	if m.readOnly {
		readOnly = "yes"
		writable = "no"
	}
	f, err := os.Create(m.confPath)
	if err != nil {
		return fmt.Errorf("storage: create smb.conf: %w", err)
	}
	defer f.Close()
	return tmpl.Execute(f, data{
		StoragePath: m.cfg.StoragePath,
		SambaUser:   m.cfg.SambaUser,
		LogFile:     filepath.Join(m.cfg.ConfDir, "smb.log"),
		ReadOnly:    readOnly,
		Writable:    writable,
	})
}

func (m *Manager) SetSambaPassword() error {
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("storage: pipe: %w", err)
	}
	_, _ = fmt.Fprintf(w, "%s\n%s\n", m.cfg.SambaPass, m.cfg.SambaPass)
	w.Close()
	cmd := exec.Command("smbpasswd", "-a", "-s", m.cfg.SambaUser)
	cmd.Stdin = r
	out, err := cmd.CombinedOutput()
	r.Close()
	if err != nil {
		return fmt.Errorf("storage: smbpasswd: %w — %s", err, out)
	}
	return nil
}

func (m *Manager) StartSMB() error {
	if !m.HasSMB() {
		return fmt.Errorf("storage: SMB not configured")
	}
	if err := m.writeSMBConfig(); err != nil {
		return err
	}
	m.smbCmd = exec.Command(
		"smbd",
		"--foreground",
		"--no-process-group",
		fmt.Sprintf("--configfile=%s", m.confPath),
	)
	m.smbCmd.Stdout = os.Stdout
	m.smbCmd.Stderr = os.Stderr
	if err := m.smbCmd.Start(); err != nil {
		return fmt.Errorf("storage: start smbd: %w", err)
	}
	return nil
}

func (m *Manager) Reload() error {
	if m.smbCmd == nil || m.smbCmd.Process == nil {
		return fmt.Errorf("storage: smbd not running")
	}
	if err := m.writeSMBConfig(); err != nil {
		return err
	}
	return m.smbCmd.Process.Signal(syscall.SIGHUP)
}

func (m *Manager) StopSMB() {
	if m.smbCmd != nil && m.smbCmd.Process != nil {
		_ = m.smbCmd.Process.Kill()
		_ = m.smbCmd.Wait()
	}
}

func (m *Manager) UpdateQuota(quotaBytes int64) {
	m.cfg.QuotaBytes = quotaBytes
	_ = m.CheckAndEnforceQuota()
}

func (m *Manager) EnableSMB(cfg Config) error {
	m.cfg = cfg
	if cfg.ConfDir != "" {
		m.confPath = filepath.Join(cfg.ConfDir, "smb.conf")
		if err := os.MkdirAll(cfg.ConfDir, 0o700); err != nil {
			return fmt.Errorf("storage: mkdir conf: %w", err)
		}
	}
	if cfg.StoragePath != "" {
		if err := os.MkdirAll(cfg.StoragePath, 0o750); err != nil {
			return fmt.Errorf("storage: mkdir storage: %w", err)
		}
	}
	return nil
}
