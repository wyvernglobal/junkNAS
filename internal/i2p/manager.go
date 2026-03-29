// Package i2p manages the i2pd router subprocess and tunnel configuration.
// JunkNAS runs i2pd as a child process. All outbound inter-node HTTP traffic
// is routed through i2pd's SOCKS5 proxy on 127.0.0.1:4447.
//
// i2pd datadir layout (all under configDir, e.g. /var/lib/junknas/i2p):
//
//	i2pd.conf     — main router config (auto-generated)
//	tunnels.conf  — server + client tunnels (auto-generated, hot-reloaded via SIGHUP)
//	i2pd.log      — router log
//	smb-server.dat — our persistent I2P destination key (written by i2pd)
//	destinations/, netDb/, addressbook/ — i2pd runtime state (written by i2pd)
//
// The parent of configDir also gets a .i2pd symlink pointing at configDir so
// that i2pd's $HOME/.i2pd fallback (used when the Debian package ignores
// --datadir) resolves correctly.
package i2p

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"text/template"
	"time"
)

const (
	// SOCKS5Addr is the proxy all outbound I2P HTTP goes through.
	SOCKS5Addr = "127.0.0.1:4447"

	// startupGrace is how long we wait for i2pd to signal readiness via log.
	startupGrace = 15 * time.Second

	// b32Suffix is appended to the base32 hash to form a full destination.
	b32Suffix = ".b32.i2p"
)

// TunnelPeer describes a remote peer needing a client tunnel entry.
type TunnelPeer struct {
	Identity  string // e.g. "apple storm delta"
	B32       string // e.g. "abc123….b32.i2p"
	LocalPort int    // localhost port mapped to peer's remote SMB (445)
}

// Manager owns the i2pd subprocess and generated config files.
type Manager struct {
	configDir string
	cmd       *exec.Cmd
	b32       string // cached once keyfile is readable
}

// New creates a Manager rooted at configDir and writes initial config files.
// serverPort is the local Samba port (usually 445) — writing the server tunnel
// immediately ensures i2pd generates the destination keyfile on first boot.
func New(configDir string, serverPort int) (*Manager, error) {
	if err := os.MkdirAll(configDir, 0o750); err != nil {
		return nil, fmt.Errorf("i2p: mkdir %s: %w", configDir, err)
	}
	// Ensure the directory is writable by the current process.
	// It may have been created by a prior root run.
	if err := os.Chmod(configDir, 0o750); err != nil {
		// Non-fatal — the ExecStartPre in the systemd unit handles this.
		fmt.Fprintf(os.Stderr, "[i2p] warn: chmod %s: %v\n", configDir, err)
	}

	// Create $parent/.i2pd → configDir symlink so i2pd's $HOME/.i2pd fallback
	// (used when the Debian package ignores --datadir) finds our config.
	homeDir := filepath.Dir(configDir)
	dotI2pd := filepath.Join(homeDir, ".i2pd")
	if _, err := os.Lstat(dotI2pd); os.IsNotExist(err) {
		if err := os.Symlink(configDir, dotI2pd); err != nil {
			fmt.Fprintf(os.Stderr, "[i2p] warn: .i2pd symlink: %v\n", err)
		}
	}

	m := &Manager{configDir: configDir}
	if err := m.writeI2PDConf(); err != nil {
		return nil, err
	}
	// Always write server tunnel so i2pd creates the destination keyfile.
	if err := m.writeTunnelsConf(serverPort, nil); err != nil {
		return nil, err
	}
	return m, nil
}

// Start launches i2pd and waits up to startupGrace for it to signal readiness.
func (m *Manager) Start() error {
	i2pdBin, err := findI2PD()
	if err != nil {
		return err
	}

	// Preflight: verify datadir is writable before handing off to i2pd.
	testDir := filepath.Join(m.configDir, ".writetest")
	if mkErr := os.Mkdir(testDir, 0o700); mkErr != nil {
		return fmt.Errorf(
			"i2p: datadir %s is not writable (uid=%d): %w\n"+
				"  Fix: sudo chown -R $(id -un) %s && sudo chmod -R u+rwX %s",
			m.configDir, os.Getuid(), mkErr, m.configDir, m.configDir,
		)
	}
	os.Remove(testDir)

	confPath    := filepath.Join(m.configDir, "i2pd.conf")
	tunnelsPath := filepath.Join(m.configDir, "tunnels.conf")

	m.cmd = exec.Command(i2pdBin,
		"--conf="+confPath,
		"--tunconf="+tunnelsPath,
		"--datadir="+m.configDir,
		"--log=file",
		"--logfile="+filepath.Join(m.configDir, "i2pd.log"),
		"--loglevel=warn",
	)

	// Set HOME so i2pd's $HOME/.i2pd fallback points to our symlink.
	// Also set I2PD_DATADIR for any future i2pd versions that respect it.
	homeDir := filepath.Dir(m.configDir)
	m.cmd.Env = append(os.Environ(),
		"HOME="+homeDir,
		"I2PD_DATADIR="+m.configDir,
	)

	// Pipe stdout+stderr — tee to logfile and scan for readiness.
	logPath := filepath.Join(m.configDir, "i2pd.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("i2p: open log: %w", err)
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		logFile.Close()
		return fmt.Errorf("i2p: pipe: %w", err)
	}
	m.cmd.Stdout = pw
	m.cmd.Stderr = pw

	if err := m.cmd.Start(); err != nil {
		pr.Close(); pw.Close(); logFile.Close()
		return fmt.Errorf("i2p: start i2pd: %w", err)
	}
	pw.Close()

	ready := make(chan struct{}, 1)
	go func() {
		defer pr.Close()
		defer logFile.Close()
		scanner := bufio.NewScanner(pr)
		for scanner.Scan() {
			line := scanner.Text()
			logFile.WriteString(line + "\n")
			if strings.Contains(line, "Bootstrapping complete") ||
				strings.Contains(line, "Router info saved") ||
				strings.Contains(line, "Connected") ||
				strings.Contains(line, "Data directory") {
				select {
				case ready <- struct{}{}:
				default:
				}
			}
		}
	}()

	select {
	case <-ready:
	case <-time.After(startupGrace):
	}

	// Attempt to resolve B32 — may not be ready yet on first boot.
	b32, err := pollB32(filepath.Join(m.configDir, "smb-server.dat"), 120*time.Second)
	if err != nil {
		// Non-fatal — daemon.retryB32() will keep trying.
		fmt.Fprintf(os.Stderr, "[i2p] B32 not yet available: %v\n", err)
		return nil
	}
	m.b32 = b32
	return nil
}

// Stop sends SIGTERM to i2pd and waits up to 10s before killing.
func (m *Manager) Stop() {
	if m.cmd == nil || m.cmd.Process == nil {
		return
	}
	_ = m.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- m.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = m.cmd.Process.Kill()
	}
}

// B32Address returns this node's .b32.i2p address, or empty if not yet ready.
func (m *Manager) B32Address() string {
	if m.b32 != "" {
		return m.b32
	}
	b32, err := b32FromKeyFile(filepath.Join(m.configDir, "smb-server.dat"))
	if err == nil {
		m.b32 = b32
	}
	return m.b32
}

// ReloadTunnels rewrites tunnels.conf and sends SIGHUP so i2pd picks up
// new/removed peers without restarting.
func (m *Manager) ReloadTunnels(smbServerPort int, peers []TunnelPeer) error {
	if err := m.writeTunnelsConf(smbServerPort, peers); err != nil {
		return err
	}
	if m.cmd != nil && m.cmd.Process != nil {
		if err := m.cmd.Process.Signal(syscall.SIGHUP); err != nil {
			return fmt.Errorf("i2p: SIGHUP: %w", err)
		}
	}
	return nil
}

// ── config templates ──────────────────────────────────────────────────────

const i2pdConfTmpl = `# JunkNAS i2pd configuration — auto-generated, do not edit.

[general]
datadir   = {{.DataDir}}
tunconf   = {{.TunnelsConf}}
loglevel  = warn
logfile   = {{.LogFile}}

[ntcp2]
enabled = true

[ssu2]
enabled = true

[http]
enabled = false

[httpproxy]
enabled = false

[socksproxy]
enabled = true
address  = 127.0.0.1
port     = 4447

[sam]
enabled = false

[bob]
enabled = false

[i2cp]
enabled = false

[limits]
transittunnels = 300

[trust]
enabled = false
`

const tunnelsConfTmpl = `# JunkNAS tunnel configuration — auto-generated.
# Hot-reloaded via SIGHUP when peers change.
# Keys paths are relative so i2pd resolves them against its datadir.
{{if gt .ServerPort 0}}
[junknas-smb-server]
type              = server
host              = 127.0.0.1
port              = {{.ServerPort}}
keys              = smb-server.dat
inbound.quantity  = 3
outbound.quantity = 3
inbound.length    = 1
outbound.length   = 1
{{end}}
{{range .Peers}}
[junknas-peer-{{.SafeName}}]
type            = client
address         = {{.B32}}
port            = {{.LocalPort}}
destination     = {{.B32}}
destinationport = 445
keys            = peer-{{.SafeName}}.dat
{{end}}
`

type i2pdConfData struct {
	DataDir     string
	TunnelsConf string
	LogFile     string
}

type tunnelsConfData struct {
	ServerPort int
	Peers      []tunnelPeerEntry
}

type tunnelPeerEntry struct {
	SafeName  string
	B32       string
	LocalPort int
}

func (m *Manager) writeI2PDConf() error {
	tmpl := template.Must(template.New("i2pd").Parse(i2pdConfTmpl))
	f, err := os.Create(filepath.Join(m.configDir, "i2pd.conf"))
	if err != nil {
		return fmt.Errorf("i2p: create i2pd.conf: %w", err)
	}
	defer f.Close()
	return tmpl.Execute(f, i2pdConfData{
		DataDir:     m.configDir,
		TunnelsConf: filepath.Join(m.configDir, "tunnels.conf"),
		LogFile:     filepath.Join(m.configDir, "i2pd.log"),
	})
}

func (m *Manager) writeTunnelsConf(serverPort int, peers []TunnelPeer) error {
	tmpl := template.Must(template.New("tunnels").Parse(tunnelsConfTmpl))
	data := tunnelsConfData{ServerPort: serverPort}
	for _, p := range peers {
		data.Peers = append(data.Peers, tunnelPeerEntry{
			SafeName:  strings.ReplaceAll(p.Identity, " ", "-"),
			B32:       p.B32,
			LocalPort: p.LocalPort,
		})
	}
	f, err := os.Create(filepath.Join(m.configDir, "tunnels.conf"))
	if err != nil {
		return fmt.Errorf("i2p: create tunnels.conf: %w", err)
	}
	defer f.Close()
	return tmpl.Execute(f, data)
}

// pollB32 retries b32FromKeyFile until the keyfile exists or timeout elapses.
func pollB32(keyFile string, timeout time.Duration) (string, error) {
	fmt.Fprintf(os.Stderr, "[i2p] waiting for keyfile: %s\n", keyFile)
	deadline := time.Now().Add(timeout)
	attempt := 0
	for time.Now().Before(deadline) {
		b32, err := b32FromKeyFile(keyFile)
		if err == nil {
			fmt.Fprintf(os.Stderr, "[i2p] keyfile ready (attempt %d): %s\n", attempt+1, b32)
			return b32, nil
		}
		if attempt%5 == 0 {
			fmt.Fprintf(os.Stderr, "[i2p] keyfile not ready yet: %v\n", err)
		}
		attempt++
		time.Sleep(3 * time.Second)
	}
	return "", fmt.Errorf("keyfile %s not ready after %s", keyFile, timeout)
}

// findI2PD locates the i2pd binary.
func findI2PD() (string, error) {
	if path, err := exec.LookPath("i2pd"); err == nil {
		return path, nil
	}
	for _, c := range []string{
		"/usr/sbin/i2pd", "/usr/local/sbin/i2pd",
		"/usr/bin/i2pd", "/usr/local/bin/i2pd",
	} {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf(
		"i2pd not found — install with: apt install i2pd",
	)
}
