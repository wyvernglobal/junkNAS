// JunkNAS — distributed private cloud over I2P
//
// Usage:
//
//	junknas                   launch daemon + Qt6 GUI (default on desktop)
//	junknas --tui             launch daemon + terminal UI (good for servers)
//	junknas --daemon          daemon only, no UI (for systemd service use)
//	junknas --tui-only        TUI connecting to an already-running daemon
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/junknas/junknas/internal/daemon"
	"github.com/junknas/junknas/tui"
)

// Version is injected at build time via -ldflags.
var Version = "dev"

func main() {
	var (
		tuiMode    = flag.Bool("tui", false, "Launch with terminal UI instead of Qt6 GUI")
		daemonOnly = flag.Bool("daemon", false, "Run daemon only — no UI (for systemd)")
		tuiOnly    = flag.Bool("tui-only", false, "TUI only — connect to an existing daemon")
		dataDir    = flag.String("data", defaultDataDir(), "Data/state directory")
		storage    = flag.String("storage", "", "Storage path (empty = leech mode, default)")
		// Quota has no built-in default: the operator must choose an appropriate
		// value for their disk.  A value of 0 means leech / no quota enforced.
		quotaGB = flag.Int64("quota", 0, "Storage quota in GiB (0 = leech / unlimited)")
		smbUser = flag.String("smb-user", "junknas", "Samba username")
		smbPass = flag.String("smb-pass", "", "Samba password (or set JUNKNAS_SMB_PASS)")
		version = flag.Bool("version", false, "Print version and exit")
	)
	flag.Parse()

	if *version {
		fmt.Printf("JunkNAS %s\n", Version)
		return
	}

	// ── TUI-only: attach to an already-running daemon ─────────────────────
	if *tuiOnly {
		lockPath := "/tmp/junknas.lock"
		fmt.Fprintf(os.Stderr, "JunkNAS TUI — looking for daemon lock file at %s\n", lockPath)

		if err := waitForLockFile(15 * time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "\nERROR: daemon not found.\n")
			fmt.Fprintf(os.Stderr, "  Lock file:  %s\n", lockPath)
			fmt.Fprintf(os.Stderr, "  Start with: systemctl start junknas\n")
			fmt.Fprintf(os.Stderr, "  Or run:     junknasd --daemon\n")
			os.Exit(1)
		}

		fmt.Fprintln(os.Stderr, "Daemon found — launching TUI...")
		if err := tui.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "TUI exited with error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// ── Resolve Samba password ─────────────────────────────────────────────
	pass := *smbPass
	if pass == "" {
		pass = os.Getenv("JUNKNAS_SMB_PASS")
	}
	if pass == "" {
		secretFile := os.Getenv("JUNKNAS_SMB_PASS_FILE")
		if secretFile == "" {
			secretFile = "/etc/junknas/smb.secret"
		}
		if data, err := os.ReadFile(secretFile); err == nil {
			pass = string(data)
		}
	}
	if pass == "" && *storage != "" {
		pass = promptPassword("Samba password: ")
	}

	// ── Build daemon ───────────────────────────────────────────────────────
	cfg := daemon.Config{
		DataDir:     *dataDir,
		StoragePath: *storage,
		QuotaBytes:  *quotaGB << 30,
		SambaUser:   *smbUser,
		SambaPass:   pass,
	}

	d, err := daemon.New(cfg)
	if err != nil {
		log.Fatalf("junknas: %v", err)
	}

	// ── Graceful shutdown ──────────────────────────────────────────────────
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("junknas: received %s — shutting down", sig)
		d.Stop()
		os.Exit(0)
	}()

	// ── Launch UI alongside daemon ─────────────────────────────────────────
	if !*daemonOnly {
		if *tuiMode {
			go func() {
				waitForLockFile(10 * time.Second)
				if err := tui.Run(); err != nil {
					log.Printf("junknas: tui: %v", err)
				}
				d.Stop()
				os.Exit(0)
			}()
		} else {
			go launchQtGUI()
		}
	}

	// ── Start daemon (blocks) ──────────────────────────────────────────────
	if err := d.Start(); err != nil {
		log.Fatalf("junknas: daemon: %v", err)
	}
}

// defaultDataDir returns ~/.junknas, falling back to /var/lib/junknas.
func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/var/lib/junknas"
	}
	return filepath.Join(home, ".junknas")
}

// waitForLockFile polls until /tmp/junknas.lock exists or timeout elapses.
// Returns an error if the file never appears within the timeout.
func waitForLockFile(timeout time.Duration) error {
	lockPath := "/tmp/junknas.lock"
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(lockPath); err == nil {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("lock file %s not found after %s", lockPath, timeout)
}

// launchQtGUI exec's the junknas-gui binary located next to the daemon.
func launchQtGUI() {
	exe, err := os.Executable()
	if err != nil {
		log.Printf("junknas: cannot locate executable: %v", err)
		return
	}
	guiPath := filepath.Join(filepath.Dir(exe), "junknas-gui")
	if _, err := os.Stat(guiPath); err != nil {
		log.Printf("junknas: Qt GUI not found at %s (headless mode)", guiPath)
		return
	}
	proc, err := os.StartProcess(guiPath, []string{guiPath}, &os.ProcAttr{
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	})
	if err != nil {
		log.Printf("junknas: could not launch Qt GUI: %v", err)
		return
	}
	_, _ = proc.Wait()
}

// promptPassword reads a password from stdin.
func promptPassword(prompt string) string {
	fmt.Fprint(os.Stderr, prompt)
	var pass string
	if _, err := fmt.Fscan(os.Stdin, &pass); err != nil {
		return ""
	}
	return pass
}
