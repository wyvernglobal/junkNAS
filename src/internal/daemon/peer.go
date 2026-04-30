package daemon

import "time"

type Role string

const (
	RoleStorage Role = "storage"
	RoleLeech   Role = "leech"
)

type Status string

const (
	StatusHealthy     Status = "healthy"
	StatusDegraded    Status = "degraded"
	StatusUnreachable Status = "unreachable"
	StatusPending     Status = "pending"
)

type Self struct {
	B32         string    `json:"b32"`
	SMBB32      string    `json:"smb_b32"`
	Phrase      [3]string `json:"phrase"`
	PhraseHash  string    `json:"phrase_hash"`
	Role        Role      `json:"role"`
	QuotaBytes  int64     `json:"quota_bytes"`
	StoragePath string    `json:"storage_path"`
	JoinedAt    time.Time `json:"joined_at"`
	APIPort     int       `json:"api_port"`
}

type Peer struct {
	B32            string    `json:"b32"`
	SMBB32         string    `json:"smb_b32"`
	Phrase         [3]string `json:"phrase"`
	PhraseHash     string    `json:"phrase_hash"`
	Role           Role      `json:"role"`
	QuotaBytes     int64     `json:"quota_bytes"`
	StoragePath    string    `json:"storage_path"`
	LocalMountPort int       `json:"local_mount_port"`
	LastSeen       time.Time `json:"last_seen"`
	Status         Status    `json:"status"`
	AddedAt        time.Time `json:"added_at"`
}

func (p *Peer) Identity() string {
	return p.Phrase[0] + " " + p.Phrase[1] + " " + p.Phrase[2]
}

func (p *Peer) IsStorage() bool { return p.Role == RoleStorage }

func (p *Peer) DirName() string {
	return p.Phrase[0] + "-" + p.Phrase[1] + "-" + p.Phrase[2]
}

type PendingInvite struct {
	PhraseHash string    `json:"phrase_hash"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func (inv *PendingInvite) IsExpired() bool {
	return time.Now().After(inv.ExpiresAt)
}
