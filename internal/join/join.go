// Package join implements the JunkNAS node-join protocol.
//
// Flow overview:
//
//  1. Existing node A calls GenerateInvite() → gets its API B32 + 3-word phrase.
//  2. User manually carries API-B32 + phrase to new node B (out-of-band).
//  3. B calls SendJoinRequest(targetAPIB32, phrase, …) which POSTs to A over
//     I2P via the SOCKS5 proxy.  The URL is http://<A-API-B32>/v1/join.
//  4. A's HTTP handler calls HandleJoin() → validates token, registers B with
//     BOTH its API B32 (for future HTTP calls) and SMB B32 (for tunnel config),
//     broadcasts AnnounceRequest to every other peer.
//  5. Each peer calls HandleAnnounce() → registers B locally.
//  6. B receives the full peer list in the JoinResponse and adds them all.
//
// SMB vs API B32:
//   - API B32  (api-server.dat key)  — used as HTTP endpoint via SOCKS5.
//     All JSON requests (join, announce, heartbeat) go here.
//   - SMB B32  (smb-server.dat key)  — used as `destination` in the i2pd
//     client tunnel config so the local mount port connects to Samba.
package join

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/junknas/junknas/internal/registry"
	"github.com/junknas/junknas/internal/words"
)

const inviteTTL = 10 * time.Minute

// ── wire types ────────────────────────────────────────────────────────────

// Invitation is returned to the UI when the user clicks "Add Node".
// B32 is the inviting node's API B32 — what the new node must paste into
// the "Join Cloud" form.
type Invitation struct {
	B32    string    `json:"b32"` // API B32 of this node
	Phrase [3]string `json:"phrase"`
	Hash   string    `json:"hash"`
}

// JoinRequest is sent by a new node to an existing one.
// Both B32 addresses of the joining node are included so the target can:
//   - Register the API B32 for future HTTP calls.
//   - Register the SMB B32 for building the I2P client tunnel.
type JoinRequest struct {
	Token      string        `json:"token"`       // SHA-256(phrase)
	B32        string        `json:"b32"`         // new node's API B32
	SMBB32     string        `json:"smb_b32"`     // new node's SMB B32
	Phrase     [3]string     `json:"phrase"`      // new node's identity phrase
	Role       registry.Role `json:"role"`
	QuotaBytes int64         `json:"quota_bytes"`
}

// JoinResponse is returned to the joining node.
type JoinResponse struct {
	Peers   []*registry.Peer `json:"peers"`
	SelfB32 string           `json:"self_b32"` // API B32 of the responding node
}

// AnnounceRequest is broadcast from the first-contact node to every other peer
// so they can register the new node and rebuild their tunnel configs.
type AnnounceRequest struct {
	B32        string        `json:"b32"`         // new node's API B32
	SMBB32     string        `json:"smb_b32"`     // new node's SMB B32
	Phrase     [3]string     `json:"phrase"`
	PhraseHash string        `json:"phrase_hash"`
	Role       registry.Role `json:"role"`
	QuotaBytes int64         `json:"quota_bytes"`
}

// ── Protocol ──────────────────────────────────────────────────────────────

// Protocol handles all join handshake logic for a single node.
type Protocol struct {
	reg        *registry.Registry
	httpClient *http.Client // SOCKS5-aware; set via SetHTTPClient
}

// New creates a Protocol. Call SetHTTPClient before any outbound requests.
func New(reg *registry.Registry) *Protocol {
	return &Protocol{
		reg:        reg,
		httpClient: &http.Client{Timeout: 90 * time.Second},
	}
}

// SetHTTPClient replaces the HTTP client used for all outbound peer calls.
// Should be called with i2p.NewHTTPClient() once i2pd is running.
func (p *Protocol) SetHTTPClient(c *http.Client) {
	p.httpClient = c
}

// ── invite side (existing node) ───────────────────────────────────────────

// GenerateInvite creates a pending invite and returns it for display in the UI.
// The B32 in the returned Invitation is this node's API B32 address — the
// address the joining node must POST its JoinRequest to.
func (p *Protocol) GenerateInvite() (*Invitation, error) {
	phrase, err := words.Generate()
	if err != nil {
		return nil, fmt.Errorf("join: generate phrase: %w", err)
	}
	hash := phrase.Hash()
	if err := p.reg.AddInvite(registry.PendingInvite{
		PhraseHash: hash,
		ExpiresAt:  time.Now().Add(inviteTTL),
	}); err != nil {
		return nil, fmt.Errorf("join: store invite: %w", err)
	}
	self := p.reg.Self()
	return &Invitation{
		B32:    self.B32, // API B32 — what the new node will POST to
		Phrase: phrase,
		Hash:   hash,
	}, nil
}

// HandleJoin validates an inbound join request, registers the new peer with
// both its API and SMB B32 addresses, and broadcasts an announce to all
// existing peers.
func (p *Protocol) HandleJoin(req *JoinRequest) (*JoinResponse, error) {
	if !p.reg.ConsumeInvite(req.Token) {
		return nil, fmt.Errorf("join: invalid or expired token")
	}
	newPeer := &registry.Peer{
		B32:        req.B32,    // API B32 — HTTP endpoint
		SMBB32:     req.SMBB32, // SMB B32 — for I2P client tunnel
		Phrase:     req.Phrase,
		PhraseHash: req.Token,
		Role:       req.Role,
		QuotaBytes: req.QuotaBytes,
		Status:     registry.StatusPending,
	}
	if err := p.reg.AddPeer(newPeer); err != nil {
		return nil, fmt.Errorf("join: register peer: %w", err)
	}
	go p.broadcastAnnounce(&AnnounceRequest{
		B32:        req.B32,
		SMBB32:     req.SMBB32,
		Phrase:     req.Phrase,
		PhraseHash: req.Token,
		Role:       req.Role,
		QuotaBytes: req.QuotaBytes,
	}, req.B32 /* excludeB32 */)

	self := p.reg.Self()
	return &JoinResponse{
		Peers:   p.reg.Peers(),
		SelfB32: self.B32, // API B32
	}, nil
}

// HandleAnnounce registers an announced peer received from another node.
func (p *Protocol) HandleAnnounce(req *AnnounceRequest) error {
	if p.reg.HasPeer(req.B32) {
		_ = p.reg.UpdatePeerStatus(req.B32, registry.StatusPending)
		return nil
	}
	return p.reg.AddPeer(&registry.Peer{
		B32:        req.B32,
		SMBB32:     req.SMBB32,
		Phrase:     req.Phrase,
		PhraseHash: req.PhraseHash,
		Role:       req.Role,
		QuotaBytes: req.QuotaBytes,
		Status:     registry.StatusPending,
	})
}

// ── joining side (new node) ───────────────────────────────────────────────

// SendJoinRequest dials the target node's API endpoint over I2P (via SOCKS5),
// authenticates with the phrase hash, and receives back the full peer list.
//
// targetAPIB32 must be the inviting node's API B32 address (e.g.
// "abc123.b32.i2p") — the one shown in the "Add Node" screen.
// HTTP requests go to http://<targetAPIB32>/v1/join via the SOCKS5 proxy.
func (p *Protocol) SendJoinRequest(
	targetAPIB32 string,
	phrase words.Phrase,
	role registry.Role,
	quotaBytes int64,
) (*JoinResponse, error) {
	self := p.reg.Self()
	req := &JoinRequest{
		Token:      phrase.Hash(),
		B32:        self.B32,    // our API B32
		SMBB32:     self.SMBB32, // our SMB B32
		Phrase:     self.Phrase,
		Role:       role,
		QuotaBytes: quotaBytes,
	}

	// POST to the target's API endpoint over I2P (SOCKS5).
	// The .b32.i2p hostname is resolved by the SOCKS5 proxy; i2pd routes the
	// connection to the api-server tunnel on the target node (port 36789 locally).
	url := fmt.Sprintf("http://%s/v1/join", targetAPIB32)
	resp, err := p.postJSON(url, req)
	if err != nil {
		return nil, fmt.Errorf("join: POST to %s: %w", targetAPIB32, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("join: target replied %s", resp.Status)
	}
	var jr JoinResponse
	if err := json.NewDecoder(resp.Body).Decode(&jr); err != nil {
		return nil, fmt.Errorf("join: decode response: %w", err)
	}

	// Register every received peer that isn't us (keyed by API B32).
	for _, peer := range jr.Peers {
		if peer.B32 != self.B32 {
			_ = p.reg.AddPeer(peer)
		}
	}
	return &jr, nil
}

// broadcastAnnounce fans out an AnnounceRequest to all known peers except
// the one that just joined. HTTP POSTs go to each peer's API B32 via SOCKS5.
// Best-effort — errors are silently dropped.
func (p *Protocol) broadcastAnnounce(req *AnnounceRequest, excludeB32 string) {
	for _, peer := range p.reg.Peers() {
		if peer.B32 == excludeB32 {
			continue
		}
		// peer.B32 is the API B32 — use it for HTTP calls via SOCKS5.
		url := fmt.Sprintf("http://%s/v1/peer_announce", peer.B32)
		resp, err := p.postJSON(url, req)
		if err == nil {
			resp.Body.Close()
		}
	}
}

// postJSON marshals payload to JSON and POSTs it through the SOCKS5 client.
func (p *Protocol) postJSON(url string, payload any) (*http.Response, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return p.httpClient.Do(req)
}
