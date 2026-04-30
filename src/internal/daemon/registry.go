package daemon

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
	mountPortStart = 10445
)

type store struct {
	Self           *Self           `json:"self"`
	Peers          []*Peer         `json:"peers"`
	PendingInvites []PendingInvite `json:"pending_invites"`
}

type Registry struct {
	mu             sync.RWMutex
	self           *Self
	peers          map[string]*Peer
	pendingInvites []PendingInvite
	dataDir        string
}

func NewRegistry(dataDir string) (*Registry, error) {
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

func (r *Registry) SetSelf(s *Self) error {
	r.mu.Lock()
	r.self = s
	r.mu.Unlock()
	return r.save()
}

func (r *Registry) Self() *Self {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.self
}

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

func (r *Registry) RemovePeer(b32 string) error {
	r.mu.Lock()
	delete(r.peers, b32)
	r.mu.Unlock()
	return r.save()
}

func (r *Registry) Peer(b32 string) *Peer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.peers[b32]
}

func (r *Registry) Peers() []*Peer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Peer, 0, len(r.peers))
	for _, p := range r.peers {
		out = append(out, p)
	}
	return out
}

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

func (r *Registry) AddInvite(inv PendingInvite) error {
	r.mu.Lock()
	r.pruneInvites()
	r.pendingInvites = append(r.pendingInvites, inv)
	r.mu.Unlock()
	return r.save()
}

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

func (r *Registry) HasPeer(b32 string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.peers[b32]
	return ok
}

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

func (r *Registry) pruneInvites() {
	var active []PendingInvite
	for _, inv := range r.pendingInvites {
		if !inv.IsExpired() {
			active = append(active, inv)
		}
	}
	r.pendingInvites = active
}

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
