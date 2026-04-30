package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	InviteTTL      = 10 * time.Minute
	registryFile   = "registry.json"
	mountPortStart = 10445 // first local port used for peer SMB tunnels
)

// store is the serialised form written to disk.
type store struct {
	Self           *Self           `json:"self"`
	Peers          []*Peer         `json:"peers"`
	PendingInvites []PendingInvite `json:"pending_invites"`
}

// Registry is the in-memory node registry with JSON persistence.
type Registry struct {
	mu             sync.RWMutex
	self           *Self
	peers          map[string]*Peer // keyed by b32
	pendingInvites []PendingInvite
	dataDir        string
}

// New creates (or loads) the registry rooted at dataDir.
func New(dataDir string) (*Registry, error) {
	r := &Registry{
		peers:   make(map[string]*Peer),
		dataDir: dataDir,
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("registry: mkdir %s: %w", dataDir, err)
	}
	if err := r.load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("registry: load: %w", err)
	}
	return r, nil
}

// SetSelf persists the node's own identity.
func (r *Registry) SetSelf(s *Self) error {
	r.mu.Lock()
	r.self = s
	r.mu.Unlock()
	return r.save()
}

// Self returns this node's identity (nil before first SetSelf).
func (r *Registry) Self() *Self {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.self
}

// AddPeer adds or updates a peer and persists.
func (r *Registry) AddPeer(p *Peer) error {
	r.mu.Lock()
	if _, exists := r.peers[p.B32]; !exists {
		p.LocalMountPort = r.nextMountPort()
		p.AddedAt = time.Now()
	}
	r.peers[p.B32] = p
	r.mu.Unlock()
	return r.save()
}

// RemovePeer removes a peer by b32 address.
func (r *Registry) RemovePeer(b32 string) error {
	r.mu.Lock()
	delete(r.peers, b32)
	r.mu.Unlock()
	return r.save()
}

// Peer returns a single peer or nil.
func (r *Registry) Peer(b32 string) *Peer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.peers[b32]
}

// Peers returns a snapshot of all known peers.
func (r *Registry) Peers() []*Peer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Peer, 0, len(r.peers))
	for _, p := range r.peers {
		out = append(out, p)
	}
	return out
}

// StoragePeers returns only peers that store files (excludes leeches).
func (r *Registry) StoragePeers() []*Peer {
	all := r.Peers()
	var out []*Peer
	for _, p := range all {
		if p.IsStorage() {
			out = append(out, p)
		}
	}
	return out
}

// UpdatePeerStatus records last-seen and status for a peer.
func (r *Registry) UpdatePeerStatus(b32 string, status Status) error {
	r.mu.Lock()
	if p, ok := r.peers[b32]; ok {
		p.Status = status
		if status == StatusHealthy {
			p.LastSeen = time.Now()
		}
	}
	r.mu.Unlock()
	return r.save()
}

// AddInvite stores a pending join invitation.
func (r *Registry) AddInvite(inv PendingInvite) error {
	r.mu.Lock()
	r.pruneInvites()
	r.pendingInvites = append(r.pendingInvites, inv)
	r.mu.Unlock()
	return r.save()
}

// ConsumeInvite validates and removes a pending invite by phraseHash.
// Returns false if the invite is not found or is expired.
func (r *Registry) ConsumeInvite(phraseHash string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneInvites()
	for i, inv := range r.pendingInvites {
		if inv.PhraseHash == phraseHash && !inv.IsExpired() {
			r.pendingInvites = append(r.pendingInvites[:i], r.pendingInvites[i+1:]...)
			_ = r.saveUnlocked()
			return true
		}
	}
	return false
}

// HasPeer returns true if a peer with the given b32 exists.
func (r *Registry) HasPeer(b32 string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.peers[b32]
	return ok
}

// --- persistence ---------------------------------------------------------

func (r *Registry) load() error {
	path := filepath.Join(r.dataDir, registryFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var s store
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("registry: parse %s: %w", path, err)
	}
	r.self = s.Self
	for _, p := range s.Peers {
		r.peers[p.B32] = p
	}
	r.pendingInvites = s.PendingInvites
	return nil
}

func (r *Registry) save() error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.saveUnlocked()
}

func (r *Registry) saveUnlocked() error {
	peers := make([]*Peer, 0, len(r.peers))
	for _, p := range r.peers {
		peers = append(peers, p)
	}
	s := store{
		Self:           r.self,
		Peers:          peers,
		PendingInvites: r.pendingInvites,
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("registry: marshal: %w", err)
	}
	path := filepath.Join(r.dataDir, registryFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("registry: write tmp: %w", err)
	}
	return os.Rename(tmp, path)
}

// pruneInvites removes expired invites (caller must hold mu.Lock).
func (r *Registry) pruneInvites() {
	var active []PendingInvite
	for _, inv := range r.pendingInvites {
		if !inv.IsExpired() {
			active = append(active, inv)
		}
	}
	r.pendingInvites = active
}

// nextMountPort returns the next available localhost port for a peer SMB mount.
// Caller must hold mu.Lock.
func (r *Registry) nextMountPort() int {
	used := make(map[int]bool)
	for _, p := range r.peers {
		if p.LocalMountPort > 0 {
			used[p.LocalMountPort] = true
		}
	}
	port := mountPortStart
	for used[port] {
		port++
	}
	return port
}
