
// Package i2p manages the i2pd router subprocess and tunnel configuration.
// JunkNAS runs i2pd as a child process. All outbound inter-node HTTP traffic
// is routed through i2pd's SOCKS5 proxy on 127.0.0.1:4447.
//
//
//
//	i2pd.conf       — main router config (auto-generated)
//	tunnels.conf    — server + client tunnels (auto-generated, SIGHUP to reload)
//	i2pd.log        — router log
//	smb-server.dat  — persistent I2P destination key (written by i2pd)
//	destinations/   — i2pd runtime state (written by i2pd)
//	netDb/          — i2pd network database
//	addressbook/    — i2pd address book
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
	"encoding/json"
)

const (
	// ProxyAddr is the proxy all outbound I2P HTTP goes through.
	SOCKS5Addr = "127.0.0.1:4447"

	// startupGrace is how long we wait for i2pd to signal readiness via log.
	startupGrace = 15 * time.Second

	// b32Suffix is appended to the base32 hash to form a full destination.
	b32Suffix = ".b32.i2p:36789"
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

type LockFile struct {
	ApiPort int `json:"api_port"`
}

// New creates a Manager rooted at configDir and writes initial config files.
// configDir should be <datadir>/.i2pd so i2pd operates in its natural home.
// serverPort is the local Samba port (445) — writing the server tunnel
// immediately ensures i2pd generates the destination keyfile on first boot.
func New(configDir string, serverPort int) (*Manager, error) {
	m := &Manager{configDir: configDir}
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


	softDir := "/var/lib/junknas"

	confPath := filepath.Join(m.configDir	, "i2pd.conf")
	tunnelsPath := filepath.Join(softDir, "tunnels.conf")
	logPath := filepath.Join(softDir, "i2pd.log")
	pidPath := filepath.Join(softDir, "i2pd", "i2pd.pid")

	m.cmd = exec.Command(i2pdBin,
		"--conf="+confPath,
		"--certsdir="+filepath.Join(m.configDir, "certificates"),
		"--tunconf="+tunnelsPath,
		"--datadir="+filepath.Join(softDir, "i2pd"),
		"--log=file",
		"--logfile="+logPath,
		"--loglevel=warn",
		"--pidfile="+pidPath,
	)

	m.cmd.Env = append(os.Environ(),
		"HOME="+filepath.Dir(m.configDir),
		"I2PD_DATADIR="+m.configDir,
	)
	// Pipe stdout+stderr — tee to logfile and scan for readiness.
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
	b32, err := pollB32(filepath.Join(softDir, "i2pd", "api-server.dat"), 120*time.Second)
	if err != nil {
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
	softDir := "/var/lib/junknas"
	b32, err := b32FromKeyFile(filepath.Join(softDir, "ip2d", "api-server.dat"))
	if err == nil {
		m.b32 = b32
	}
	return m.b32
}

// B32Address returns this node's .b32.i2p address, or empty if not yet ready.
func (m *Manager) SMBAddress() string {
	softDir := "/var/lib/junknas"
	b32, err := b32FromKeyFile(filepath.Join(softDir, "ip2d", "smb-server.dat"))
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



const tunnelsConfTmpl = `# JunkNAS tunnel configuration — auto-generated.
# Hot-reloaded via SIGHUP when peers change.
# Keys paths are relative so i2pd resolves them against its datadir.
{{if gt .ServerPort 0}}
[junknas-smb-server]
type              = server
host		  = 127.0.0.1
port              = {{.ServerPort}}
keys              = smb-server.dat
[junknas-api-server]
type              = http
host 		  = 127.0.0.1
port              = {{.ApiPort}}
keys              = api-server.dat
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
	ApiPort int
	Peers      []tunnelPeerEntry
}

type tunnelPeerEntry struct {
	SafeName  string
	B32       string
	LocalPort int
}


func (m *Manager) writeTunnelsConf(serverPort int, peers []TunnelPeer) error {
	softDir := "/var/lib/junknas"

	file, err := os.ReadFile("/tmp/junknas.lock")
	if err != nil {
		fmt.Println("Error reading file:", err)
		return fmt.Errorf("i2p: create tunnels.conf: %w", err)
	}

	var lockFile LockFile
	err = json.Unmarshal(file, &lockFile)
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return fmt.Errorf("i2p: create tunnels.conf: %w", err)
	}

	tmpl := template.Must(template.New("tunnels").Parse(tunnelsConfTmpl))
	data := tunnelsConfData{ServerPort: serverPort, ApiPort: lockFile.ApiPort}
	for _, p := range peers {
		data.Peers = append(data.Peers, tunnelPeerEntry{
			SafeName:  strings.ReplaceAll(p.Identity, " ", "-"),
			B32:       p.B32,
			LocalPort: p.LocalPort,
		})
	}
	f, err2 := os.Create(filepath.Join(softDir, "tunnels.conf"))
	if err2 != nil {
		return fmt.Errorf("i2p: create tunnels.conf: %w", err2)
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
	return "", fmt.Errorf("i2pd not found — install with: apt install i2pd")
}
