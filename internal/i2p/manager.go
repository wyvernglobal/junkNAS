// Package i2p manages the i2pd router subprocess and tunnel configuration.
// JunkNAS runs i2pd as a child process. All outbound inter-node HTTP traffic
// is routed through i2pd's SOCKS5 proxy on 127.0.0.1:4447.
//
// Two separate I2P server tunnels are created:
//
//	smb-server  → forwards I2P connections to 127.0.0.1:445  (Samba)
//	api-server  → forwards I2P connections to 127.0.0.1:API_PORT (REST API)
//
// Each tunnel gets its own persistent key file and therefore its own unique
// .b32.i2p address:
//
//	SMBB32  — shared with peers so they can build I2P client tunnels to mount
//	          our Samba share (SAM / client-tunnel mechanism)
//	APIB32  — shared during invite flow; peers POST join/announce requests
//	          here via the SOCKS5 proxy
package i2p

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"net/url"
	"path/filepath"
	"strings"
	"syscall"
	"text/template"
	"time"
)

const (
	
	// startupGrace is how long we wait for i2pd to signal readiness via log.
	startupGrace = 15 * time.Second

	// b32Suffix is appended to the base32-encoded SHA-256 of the destination.
	// No port — ports are handled at the call site or by the tunnel config.
	b32Suffix = ".b32.i2p"

	// softDir is the JunkNAS runtime data directory.
	softDir = "/var/lib/junknas"
)

// TunnelPeer describes a remote peer needing a client tunnel entry.
type TunnelPeer struct {
	Identity  string // e.g. "apple storm delta"
	B32       string // peer's SMB .b32.i2p address (smb-server.dat destination)
	LocalPort int    // localhost port mapped to peer's remote SMB (445)
}

// Manager owns the i2pd subprocess and generated config files.
type Manager struct {
	configDir string
	apiPort   int // local port of the REST API server
	cmd       *exec.Cmd
	smbB32    string // cached SMB B32 address (from smb-server.dat)
	apiB32    string // cached API B32 address (from api-server.dat)
	ProxAddr  *url.URL
}

// New creates a Manager and writes the initial tunnel configuration.
//
// configDir is where i2pd.conf lives (passed to i2pd --conf=).
// serverPort is the local Samba port (typically 445).
// apiPort is the local REST API port (typically 36789).
func New(configDir string, serverPort int, apiPort int) (*Manager, error) {
	m := &Manager{configDir: configDir, apiPort: apiPort}
	proxAddr,err := url.Parse("socks5h://127.0.0.1:4447")
	if err != nil {
		return nil, err
	}
	m.ProxAddr = proxAddr
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return nil, fmt.Errorf("i2p: mkdir %s: %w", configDir, err)
	}
	if err := m.writeTunnelsConf(serverPort, nil); err != nil {
		return nil, err
	}
	return m, nil
}

// Start launches i2pd and waits up to startupGrace for it to signal readiness,
// then polls until the keyfiles (and therefore B32 addresses) are available.
func (m *Manager) Start() error {
	i2pdBin, err := findI2PD()
	if err != nil {
		return err
	}

	confPath := filepath.Join(m.configDir, "i2pd.conf")
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
		pr.Close()
		pw.Close()
		logFile.Close()
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

	// Poll for API keyfile first — it signals that i2pd has processed the
	// tunnel config and both keyfiles should now exist.
	apiKeyFile := filepath.Join(softDir, "i2pd", "api-server.dat")
	apiB32, err := pollB32(apiKeyFile, 120*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[i2p] API B32 not yet available: %v\n", err)
		return nil // non-fatal; retryB32 in daemon will keep trying
	}
	m.apiB32 = apiB32
	fmt.Fprintf(os.Stderr, "[i2p] API B32: %s\n", m.apiB32)

	// SMB keyfile should be ready by the same time.
	smbKeyFile := filepath.Join(softDir, "i2pd", "smb-server.dat")
	if smbB32, err := b32FromKeyFile(smbKeyFile); err == nil {
		m.smbB32 = smbB32
		fmt.Fprintf(os.Stderr, "[i2p] SMB B32: %s\n", m.smbB32)
	} else {
		fmt.Fprintf(os.Stderr, "[i2p] SMB B32 not yet available: %v\n", err)
	}

	return nil
}

// Stop sends SIGTERM to i2pd and waits up to 10 s before killing.
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

// SMBAddress returns this node's SMB .b32.i2p address (from smb-server.dat),
// or an empty string if the keyfile is not yet available.
// The result is used as the `destination` in peer I2P client tunnel configs.
func (m *Manager) SMBAddress() string {
	if m.smbB32 != "" {
		return m.smbB32
	}
	b32, err := b32FromKeyFile(filepath.Join(softDir, "i2pd", "smb-server.dat"))
	if err == nil {
		m.smbB32 = b32
	}
	return m.smbB32
}

// APIAddress returns this node's API .b32.i2p address (from api-server.dat),
// or an empty string if the keyfile is not yet available.
// This is the address shared in invitations; peers POST to it via SOCKS5.
func (m *Manager) APIAddress() string {
	if m.apiB32 != "" {
		return m.apiB32
	}
	b32, err := b32FromKeyFile(filepath.Join(softDir, "i2pd", "api-server.dat"))
	if err == nil {
		m.apiB32 = b32
	}
	return m.apiB32
}

// B32Address returns the API B32 address (backward-compatible alias for APIAddress).
func (m *Manager) B32Address() string {
	return m.APIAddress()
}

// ReloadTunnels rewrites tunnels.conf and sends SIGHUP so i2pd picks up
// new/removed peers without a full restart.
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

// ── tunnel config template ────────────────────────────────────────────────

const tunnelsConfTmpl = `# JunkNAS tunnel configuration — auto-generated.
# Hot-reloaded via SIGHUP when peers change.
# Key paths are relative; i2pd resolves them against its --datadir.
{{if gt .ServerPort 0}}
[junknas-smb-server]
type = server
host = 127.0.0.1
port = {{.ServerPort}}
keys = smb-server.dat

[junknas-api-server]
type = server
host = 127.0.0.1
port = {{.ApiPort}}
keys = api-server.dat
{{end}}
{{range .Peers}}
[junknas-peer-{{.SafeName}}]
type            = client
address         = 127.0.0.1
port            = {{.LocalPort}}
destination     = {{.B32}}
destinationport = 445
keys            = peer-{{.SafeName}}.dat
{{end}}
`

type tunnelsConfData struct {
	ServerPort int
	ApiPort    int
	Peers      []tunnelPeerEntry
}

type tunnelPeerEntry struct {
	SafeName  string
	B32       string // peer's SMB B32 address
	LocalPort int
}

// writeTunnelsConf (re)generates tunnels.conf from the current peer list.
// It uses m.apiPort for the API server tunnel — no lock-file dependency.
func (m *Manager) writeTunnelsConf(serverPort int, peers []TunnelPeer) error {
	if err := os.MkdirAll(softDir, 0o750); err != nil {
		return fmt.Errorf("i2p: mkdir %s: %w", softDir, err)
	}

	tmpl := template.Must(template.New("tunnels").Parse(tunnelsConfTmpl))
	data := tunnelsConfData{
		ServerPort: serverPort,
		ApiPort:    m.apiPort,
	}
	for _, p := range peers {
		data.Peers = append(data.Peers, tunnelPeerEntry{
			SafeName:  strings.ReplaceAll(p.Identity, " ", "-"),
			B32:       p.B32, // SMB B32
			LocalPort: p.LocalPort,
		})
	}

	path := filepath.Join(softDir, "tunnels.conf")
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("i2p: create tunnels.conf: %w", err)
	}
	defer f.Close()
	return tmpl.Execute(f, data)
}

// ── helpers ───────────────────────────────────────────────────────────────

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

// findI2PD locates the i2pd binary in PATH and common install locations.
func findI2PD() (string, error) {
	if path, err := exec.LookPath("i2pd"); err == nil {
		return path, nil
	}
	for _, candidate := range []string{
		"/usr/sbin/i2pd", "/usr/local/sbin/i2pd",
		"/usr/bin/i2pd", "/usr/local/bin/i2pd",
	} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("i2pd not found — install with: apt install i2pd")
}
