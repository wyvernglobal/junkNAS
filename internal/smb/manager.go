package smb

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"text/template"
)

const smbConfTmpl = `# JunkNAS Samba configuration — auto-generated. Do not edit.
[global]
	workgroup = JUNKNAS
	server string = JunkNAS Node
	netbios name = JUNKNAS

	# Bind only to localhost — I2P tunnels handle external access
	interfaces = 127.0.0.1
	bind interfaces only = yes

	# SMB3 mandatory encryption
	server min protocol = SMB3
	smb encrypt = required

	# Logging
	log level = 1
	log file = {{.LogFile}}
	max log size = 10240

	# Security
	security = user
	map to guest = never
	restrict anonymous = 2

	# Performance tweaks for high-latency links
	socket options = TCP_NODELAY IPTOS_LOWLATENCY SO_RCVBUF=131072 SO_SNDBUF=131072
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
	cmd      *exec.Cmd
	readOnly bool
}

func New(cfg Config) (*Manager, error) {
	if err := os.MkdirAll(cfg.ConfDir, 0o700); err != nil {
		return nil, fmt.Errorf("smb: mkdir conf: %w", err)
	}
	if err := os.MkdirAll(cfg.StoragePath, 0o750); err != nil {
		return nil, fmt.Errorf("smb: mkdir storage: %w", err)
	}
	return &Manager{
		cfg:      cfg,
		confPath: filepath.Join(cfg.ConfDir, "smb.conf"),
	}, nil
}

func (m *Manager) UsedBytes() (int64, error) {
	out, err := exec.Command("du", "-sb", m.cfg.StoragePath).Output()
	if err != nil {
		return 0, fmt.Errorf("smb: du: %w", err)
	}
	var used int64
	fmt.Sscanf(string(out), "%d", &used)
	return used, nil
}

func (m *Manager) FreeBytes() (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(m.cfg.StoragePath, &st); err != nil {
		return 0, fmt.Errorf("smb: statfs: %w", err)
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
	exceeded := m.QuotaExceeded()
	if exceeded == m.readOnly {
		return nil
	}
	m.readOnly = exceeded
	return m.Reload()
}

func (m *Manager) WriteConfig() error {
	tmpl, err := template.New("smb").Parse(smbConfTmpl)
	if err != nil {
		return fmt.Errorf("smb: template parse: %w", err)
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
		return fmt.Errorf("smb: create smb.conf: %w", err)
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

func (m *Manager) SetPassword() error {
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("smb: pipe: %w", err)
	}
	_, _ = fmt.Fprintf(w, "%s\n%s\n", m.cfg.SambaPass, m.cfg.SambaPass)
	w.Close()
	cmd := exec.Command("smbpasswd", "-a", "-s", m.cfg.SambaUser)
	cmd.Stdin = r
	out, err := cmd.CombinedOutput()
	r.Close()
	if err != nil {
		return fmt.Errorf("smb: smbpasswd: %w — %s", err, out)
	}
	return nil
}

func (m *Manager) Start() error {
	if err := m.WriteConfig(); err != nil {
		return err
	}
	m.cmd = exec.Command(
		"smbd",
		"--foreground",
		"--no-process-group",
		fmt.Sprintf("--configfile=%s", m.confPath),
	)
	m.cmd.Stdout = os.Stdout
	m.cmd.Stderr = os.Stderr
	if err := m.cmd.Start(); err != nil {
		return fmt.Errorf("smb: start smbd: %w", err)
	}
	return nil
}

func (m *Manager) Reload() error {
	if m.cmd == nil || m.cmd.Process == nil {
		return fmt.Errorf("smb: smbd not running")
	}
	if err := m.WriteConfig(); err != nil {
		return err
	}
	return m.cmd.Process.Signal(syscall.SIGHUP)
}

func (m *Manager) Stop() {
	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Kill()
		_ = m.cmd.Wait()
	}
}

func (m *Manager) ConfPath() string { return m.confPath }

// Cfg returns a copy of the configuration.
func (m *Manager) Cfg() Config {
	return m.cfg
}

// UpdateQuota changes the quota and re‑evaluates read‑only status.
func (m *Manager) UpdateQuota(quotaBytes int64) {
	m.cfg.QuotaBytes = quotaBytes
	m.CheckAndEnforceQuota()
}
