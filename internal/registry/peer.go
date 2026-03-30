package registry

import "time"

// Role describes how a node participates in storage.
type Role string

const (
	RoleStorage Role = "storage" // full participant — stores files
	RoleLeech   Role = "leech"   // access-only — mounts cloud but stores nothing
)

// Status describes the last-known health of a peer connection.
type Status string

const (
	StatusHealthy     Status = "healthy"
	StatusDegraded    Status = "degraded"
	StatusUnreachable Status = "unreachable"
	StatusPending     Status = "pending" // tunnel not yet established
)

// Self describes this node's own identity and configuration.
type Self struct {
	// B32 is this node's API I2P destination (.b32.i2p address of the API
	// server tunnel). This is the address shared with peers so they can POST
	// join/announce requests to us over SOCKS5.
	B32 string `json:"b32"`

	// SMBB32 is this node's SMB I2P destination (.b32.i2p address of the SMB
	// server tunnel). Peers use this address when configuring their I2P client
	// tunnels to mount our Samba share.
	SMBB32 string `json:"smb_b32"`

	Phrase      [3]string `json:"phrase"`
	PhraseHash  string    `json:"phrase_hash"`
	Role        Role      `json:"role"`
	QuotaBytes  int64     `json:"quota_bytes"`
	StoragePath string    `json:"storage_path"`
	JoinedAt    time.Time `json:"joined_at"`
	APIPort     int       `json:"api_port"`
}

// Peer describes a remote node in the mesh.
type Peer struct {
	// B32 is the peer's API I2P destination. HTTP requests (join, announce,
	// heartbeat) are sent here via the SOCKS5 proxy.
	B32 string `json:"b32"`

	// SMBB32 is the peer's SMB I2P destination. This is used as the
	// `destination` in our local I2P client tunnel config so we can mount
	// the peer's Samba share via the LocalMountPort localhost port.
	SMBB32 string `json:"smb_b32"`

	Phrase         [3]string `json:"phrase"`
	PhraseHash     string    `json:"phrase_hash"`
	Role           Role      `json:"role"`
	QuotaBytes     int64     `json:"quota_bytes"`
	LocalMountPort int       `json:"local_mount_port"` // localhost port for this peer's SMB tunnel
	LastSeen       time.Time `json:"last_seen"`
	Status         Status    `json:"status"`
	AddedAt        time.Time `json:"added_at"`
}

// Identity returns the human-readable name for the peer ("word1 word2 word3").
func (p *Peer) Identity() string {
	return p.Phrase[0] + " " + p.Phrase[1] + " " + p.Phrase[2]
}

// IsStorage returns true if this peer participates in file storage.
func (p *Peer) IsStorage() bool {
	return p.Role == RoleStorage
}

// PendingInvite holds an outstanding join invitation.
type PendingInvite struct {
	PhraseHash string    `json:"phrase_hash"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// IsExpired returns true if the invite TTL has passed.
func (inv *PendingInvite) IsExpired() bool {
	return time.Now().After(inv.ExpiresAt)
}
