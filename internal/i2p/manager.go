// Package i2p manages the i2pd router subprocess and tunnel configuration.
// JunkNAS runs i2pd as a child process. All outbound inter-node HTTP traffic
// is routed through i2pd's HTTP proxy on 127.0.0.1:4444.
//
// Two separate I2P server tunnels are created:
//
//	junknas-smb-server  → forwards I2P connections to 127.0.0.1:445  (Samba)
//	junknas-api-server  → forwards I2P connections to 127.0.0.1:API_PORT (REST API)
//
// i2pd runs entirely from /var/lib/i2pd — its default system data directory.
// JunkNAS does not replace or own i2pd.conf or the log; it only appends its
// two server-tunnel stanzas to /var/lib/i2pd/tunnels.conf if they are absent,
// and rewrites the [junknas-peer-*] client-tunnel stanzas on topology changes.
//
// Keyfiles produced by i2pd live at:
//
//	/var/lib/i2pd/smb-server.dat   → SMB B32 address
//	/var/lib/i2pd/api-server.dat   → API B32 address
//	/var/lib/i2pd/peer-<name>.dat  → per-peer client tunnel keys
package i2p

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	// i2pdDataDir is the canonical i2pd data directory.  All keyfiles,
	// router info, and the tunnels.conf that JunkNAS manages live here.
	i2pdDataDir = "/var/lib/i2pd"

	// tunnelsConfPath is the tunnels configuration file JunkNAS appends to.
	tunnelsConfPath = i2pdDataDir + "/tunnels.conf"

	// startupGrace is how long we wait for i2pd to signal readiness via log.
	startupGrace = 15 * time.Second

	// b32Suffix is appended to the base32-encoded SHA-256 of the destination.
	b32Suffix = ".b32.i2p"

	// smbServerSection / apiServerSection are the INI section names JunkNAS
	// looks for in tunnels.conf to decide whether to append them.
	smbServerSection = "[junknas-smb-server]"
	apiServerSection = "[junknas-api-server]"

	// junknasPeerPrefix is the section-name prefix used for client tunnels.
	// All sections with this prefix are replaced on every ReloadTunnels call.
	junknasPeerPrefix = "[junknas-peer-"
)

// TunnelPeer describes a remote peer needing a client tunnel entry.
type TunnelPeer struct {
	Identity  string // e.g. "apple storm delta"
	B32       string // peer's SMB .b32.i2p address (smb-server.dat destination)
	LocalPort int    // localhost port mapped to peer's remote SMB (445)
}

// Manager owns the i2pd subprocess and generated config files.
type Manager struct {
	apiPort  int // local port of the REST API server
	smbPort  int // local Samba port (typically 445)
	cmd      *exec.Cmd
	smbB32   string // cached SMB B32 address (from smb-server.dat)
	apiB32   string // cached API B32 address (from api-server.dat)
	ProxAddr *url.URL
}

// New creates a Manager and ensures the two JunkNAS server-tunnel stanzas
// are present in /var/lib/i2pd/tunnels.conf, appending them if absent.
//
// serverPort is the local Samba port (typically 445).
// apiPort    is the local REST API port.
func New(_ string, serverPort int, apiPort int) (*Manager, error) {
	proxAddr, err := url.Parse("http://127.0.0.1:4444")
	if err != nil {
		return nil, err
	}
	m := &Manager{
		apiPort:  apiPort,
		smbPort:  serverPort,
		ProxAddr: proxAddr,
	}

	// Ensure the i2pd data directory exists (it normally does on a system
	// where i2pd is installed, but be defensive).
	if err := os.MkdirAll(i2pdDataDir, 0o750); err != nil {
		return nil, fmt.Errorf("i2p: mkdir %s: %w", i2pdDataDir, err)
	}

	if err := m.ensureServerTunnels(serverPort, apiPort); err != nil {
		return nil, err
	}
	return m, nil
}

// Start launches i2pd using its default system configuration from
// /var/lib/i2pd.  No custom --conf, --logfile, or --loglevel flags are
// passed — i2pd picks those up from its own i2pd.conf as installed.
//
// After i2pd starts we wait for the keyfiles to appear and cache the
// resulting B32 addresses.
// manager.go

func (m *Manager) Start() error {
    // Don't spawn i2pd — it's a system service. Just ensure our tunnel
    // stanzas are in tunnels.conf and reload the running daemon.
    if err := m.ensureServerTunnels(m.smbPort, m.apiPort); err != nil {
        return err
    }
  //  if err := m.reloadSystemI2PD(); err != nil {
        // Non-fatal: maybe it's not a systemd service, log and continue.
  //      fmt.Fprintf(os.Stderr, "[i2p] warn: could not signal system i2pd: %v\n", err)
 //   }

    // Wait for the keyfiles — i2pd generates them after processing tunnels.conf.
    apiKeyFile := filepath.Join(i2pdDataDir, "api-server.dat")
    apiB32, err := pollB32(apiKeyFile, 120*time.Second)
    if err != nil {
        fmt.Fprintf(os.Stderr, "[i2p] API B32 not yet available: %v\n", err)
        return nil // retryB32 goroutine will keep trying
    }
    m.apiB32 = apiB32
    fmt.Fprintf(os.Stderr, "[i2p] API B32: %s\n", m.apiB32)

    smbKeyFile := filepath.Join(i2pdDataDir, "smb-server.dat")
    if smbB32, err := b32FromKeyFile(smbKeyFile); err == nil {
        m.smbB32 = smbB32
        fmt.Fprintf(os.Stderr, "[i2p] SMB B32: %s\n", m.smbB32)
    }
    return nil
}

func (m *Manager) Stop() {
    // We don't own i2pd — don't kill it.
    // Optionally remove our peer tunnel stanzas and reload.
    _ = m.rewritePeerTunnels(nil)
    _ = m.reloadSystemI2PD()
}

func (m *Manager) reloadSystemI2PD() error {
    // Use systemctl to restart i2pd, this is hacky as all hell, i hate hate hate it
    // but if I do it via ANY other proccess like SIGHUP or only
    // do 1 pkill it drops the bind to the Go server port.
    cmd := exec.Command("sudo", "pkill", "i2pd", "&&", "sudo", "pkill", "i2pd", "&&", "sudo", "systemctl", "restart", "i2pd")
    out, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Errorf("systemctl restart i2pd: %w — %s", err, out)
    }
    fmt.Fprintf(os.Stderr, "[i2p] restarted system i2pd via systemctl\n")
    return nil
}



// SMBAddress returns this node's SMB .b32.i2p address (from smb-server.dat),
// or an empty string if the keyfile is not yet available.
func (m *Manager) SMBAddress() string {
	if m.smbB32 != "" {
		return m.smbB32
	}
	b32, err := b32FromKeyFile(filepath.Join(i2pdDataDir, "smb-server.dat"))
	if err == nil {
		m.smbB32 = b32
	}
	return m.smbB32
}

// APIAddress returns this node's API .b32.i2p address (from api-server.dat),
// or an empty string if the keyfile is not yet available.
func (m *Manager) APIAddress() string {
	if m.apiB32 != "" {
		return m.apiB32
	}
	b32, err := b32FromKeyFile(filepath.Join(i2pdDataDir, "api-server.dat"))
	if err == nil {
		m.apiB32 = b32
	}
	return m.apiB32
}

// B32Address returns the API B32 address (backward-compatible alias).
func (m *Manager) B32Address() string {
	return m.APIAddress()
}

// ReloadTunnels rewrites the [junknas-peer-*] client-tunnel stanzas in
// /var/lib/i2pd/tunnels.conf (leaving all other content intact) and sends
// SIGHUP so i2pd picks up the changes without a full restart.
//
// The two JunkNAS server stanzas are re-ensured on every call so that a
// manual edit that removed them is self-healed.
func (m *Manager) ReloadTunnels(smbServerPort int, peers []TunnelPeer) error {
    if err := m.ensureServerTunnels(smbServerPort, m.apiPort); err != nil {
        return err
    }
    if err := m.rewritePeerTunnels(peers); err != nil {
        return err
    }
    return nil//m.reloadSystemI2PD() // <-- was: m.cmd.Process.Signal(syscall.SIGHUP)
}
// ── tunnel config helpers ─────────────────────────────────────────────────

// ensureServerTunnels reads the existing tunnels.conf and appends the
// JunkNAS smb-server and/or api-server stanzas only if they are absent.
// The file is created if it does not yet exist.
func (m *Manager) ensureServerTunnels(smbPort, apiPort int) error {
	content := readFileOrEmpty(tunnelsConfPath)

	var buf strings.Builder
	if !strings.Contains(content, smbServerSection) {
		fmt.Fprintf(&buf, "\n%s\ntype = server\nhost = 127.0.0.1\nport = %d\nkeys = smb-server.dat\n",
			smbServerSection, smbPort)
	}
	if !strings.Contains(content, apiServerSection) {
		fmt.Fprintf(&buf, "\n%s\ntype = server\nhost = 127.0.0.1\nport = %d\nkeys = api-server.dat\n",
			apiServerSection, apiPort)
	}
	if buf.Len() == 0 {
		return nil // both stanzas already present — nothing to do
	}

	f, err := os.OpenFile(tunnelsConfPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("i2p: open tunnels.conf for append: %w", err)
	}
	defer f.Close()
	_, err = f.WriteString(buf.String())
	return err
}

// rewritePeerTunnels removes every existing [junknas-peer-*] stanza from
// tunnels.conf and appends fresh stanzas for the supplied peer list.
// All other content in the file (system tunnels, the two server stanzas,
// any user-managed sections) is preserved verbatim.
func (m *Manager) rewritePeerTunnels(peers []TunnelPeer) error {
	content := readFileOrEmpty(tunnelsConfPath)
	stripped := removeSections(content, junknasPeerPrefix)

	var buf strings.Builder
	buf.WriteString(stripped)

	for _, p := range peers {
		safeName := strings.ReplaceAll(p.Identity, " ", "-")
		fmt.Fprintf(&buf,
			"\n[junknas-peer-%s]\ntype            = client\naddress         = 127.0.0.1\nport            = %d\ndestination     = %s\ndestinationport = 445\nkeys            = peer-%s.dat\n",
			safeName, p.LocalPort, p.B32, safeName,
		)
	}

	return atomicWrite(tunnelsConfPath, buf.String())
}

// removeSections returns the contents of an INI-style file with every section
// whose header starts with prefix (e.g. "[junknas-peer-") removed, including
// all key-value lines that belong to that section.
func removeSections(content, prefix string) string {
	var out strings.Builder
	skip := false
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			// New section header — decide whether to skip it.
			skip = strings.HasPrefix(trimmed, prefix)
		}
		if !skip {
			out.WriteString(line)
			out.WriteByte('\n')
		}
	}
	return out.String()
}

// ── file helpers ──────────────────────────────────────────────────────────

// readFileOrEmpty reads a file and returns its contents, or "" on any error.
func readFileOrEmpty(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

// atomicWrite writes data to path via a temp file + rename so that a
// concurrent i2pd SIGHUP never sees a half-written file.
func atomicWrite(path, data string) error {
	tmp := path + ".junknas.tmp"
	if err := os.WriteFile(tmp, []byte(data), 0o644); err != nil {
		return fmt.Errorf("i2p: write tmp tunnels.conf: %w", err)
	}
	return os.Rename(tmp, path)
}

// ── i2pd process helpers ──────────────────────────────────────────────────

// pollB32 retries b32FromKeyFile until the keyfile exists or timeout elapses.
func pollB32(keyFile string, timeout time.Duration) (string, error) {
	fmt.Fprintf(os.Stderr, "[i2p] waiting for keyfile: %s\n", keyFile)
	deadline := time.Now().Add(timeout)
	attempt := 0
	for time.Now().Before(deadline) {
		if b32, err := b32FromKeyFile(keyFile); err == nil {
			fmt.Fprintf(os.Stderr, "[i2p] keyfile ready (attempt %d): %s\n", attempt+1, b32)
			return b32, nil
		}
		if attempt%5 == 0 {
			fmt.Fprintf(os.Stderr, "[i2p] keyfile not ready yet (attempt %d)\n", attempt)
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
