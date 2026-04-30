package mergerfs

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/junknas/junknas/internal/registry"
)

const mountPoint = "/mnt/junknas"

// Manager handles the mergerfs union mount over all peer SMB mounts.
type Manager struct {
	mountPoint string
	mounted    bool
}

// New creates a mergerfs Manager.
func New() (*Manager, error) {
	if err := os.MkdirAll(mountPoint, 0o755); err != nil {
		return nil, fmt.Errorf("mergerfs: mkdir %s: %w", mountPoint, err)
	}
	return &Manager{mountPoint: mountPoint}, nil
}

// PeerMount describes a locally-mounted peer SMB share.
type PeerMount struct {
	B32       string
	MountPath string // e.g. /mnt/junknas-peers/apple-storm-delta
	Storage   bool
}

// Rebuild tears down the existing mergerfs mount and reassembles it
// from the current set of healthy peer mounts.
func (m *Manager) Rebuild(peers []*PeerMount, selfStoragePath string) error {
	if m.mounted {
		if err := m.Unmount(); err != nil {
			return err
		}
	}

	var branches []string

	// Self storage comes first if this node stores files.
	if selfStoragePath != "" {
		branches = append(branches, selfStoragePath)
	}

	// Add each storage peer's mount path.
	for _, p := range peers {
		if p.Storage {
			branches = append(branches, p.MountPath)
		}
	}

	// Leech-mode nodes still mount everything — they just don't contribute branches.
	// If there are no branches at all we still want the leech to see the cloud.
	if len(branches) == 0 {
		// Pure leech with no known peers — nothing to mount yet.
		return nil
	}

	branchStr := strings.Join(branches, ":")
	args := []string{
		branchStr,
		m.mountPoint,
		"-o",
		strings.Join([]string{
			"func.create=mfs",        // write to most-free-space node
			"cache.files=partial",    // partial cache for performance
			"dropcacheonclose=true",
			"category.search=ff",     // search all branches on read
			"minfreespace=1G",
			"fsname=junknas",
			"allow_other",
		}, ","),
	}

	cmd := exec.Command("mergerfs", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("mergerfs: mount failed: %w", err)
	}
	m.mounted = true
	return nil
}

// Unmount tears down the mergerfs mount point.
func (m *Manager) Unmount() error {
	cmd := exec.Command("fusermount", "-u", m.mountPoint)
	if err := cmd.Run(); err != nil {
		// Try lazy unmount as a fallback.
		cmd2 := exec.Command("fusermount", "-uz", m.mountPoint)
		if err2 := cmd2.Run(); err2 != nil {
			return fmt.Errorf("mergerfs: unmount: %w (lazy: %v)", err, err2)
		}
	}
	m.mounted = false
	return nil
}

// MountPoint returns the path where the JunkNAS cloud is accessible.
func (m *Manager) MountPoint() string {
	return m.mountPoint
}

// IsMounted returns the current mount state.
func (m *Manager) IsMounted() bool {
	return m.mounted
}

// MountPeer mounts a single peer's SMB share via its localhost tunnel port.
func MountPeer(peer *registry.Peer, mountBase string, user, pass string) (string, error) {
	ident := peerDirName(peer)
	mountPath := mountBase + "/" + ident
	if err := os.MkdirAll(mountPath, 0o755); err != nil {
		return "", fmt.Errorf("mergerfs: peer mkdir %s: %w", mountPath, err)
	}

	// Use cifs-utils mount.cifs to mount the peer's SMB3 share.
	addr := fmt.Sprintf("//127.0.0.1/%s", "vault")
	opts := fmt.Sprintf(
		"port=%d,username=%s,password=%s,vers=3.0,seal,iocharset=utf8",
		peer.LocalMountPort, user, pass,
	)
	cmd := exec.Command("mount", "-t", "cifs", addr, mountPath, "-o", opts)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("mergerfs: mount peer %s: %w — %s", ident, err, out)
	}
	return mountPath, nil
}

// UnmountPeer unmounts a single peer's SMB share.
func UnmountPeer(peer *registry.Peer, mountBase string) error {
	ident := peerDirName(peer)
	mountPath := mountBase + "/" + ident
	cmd := exec.Command("umount", mountPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("mergerfs: umount peer %s: %w — %s", ident, err, out)
	}
	return nil
}

func peerDirName(p *registry.Peer) string {
	parts := [3]string(p.Phrase)
	return parts[0] + "-" + parts[1] + "-" + parts[2]
}
