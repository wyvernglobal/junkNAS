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

type Invitation struct {
	B32    string    `json:"b32"`
	Phrase [3]string `json:"phrase"`
	Hash   string    `json:"hash"`
}

type JoinRequest struct {
	Token       string        `json:"token"`
	B32         string        `json:"b32"`
	SMBB32      string        `json:"smb_b32"`
	Phrase      [3]string     `json:"phrase"`
	Role        registry.Role `json:"role"`
	QuotaBytes  int64         `json:"quota_bytes"`
	StoragePath string        `json:"storage_path"`
}

type JoinResponse struct {
	Peers   []*registry.Peer `json:"peers"`
	SelfB32 string           `json:"self_b32"`
}

type AnnounceRequest struct {
	B32         string        `json:"b32"`
	SMBB32      string        `json:"smb_b32"`
	Phrase      [3]string     `json:"phrase"`
	PhraseHash  string        `json:"phrase_hash"`
	Role        registry.Role `json:"role"`
	QuotaBytes  int64         `json:"quota_bytes"`
	StoragePath string        `json:"storage_path"`
}

type Protocol struct {
	reg        *registry.Registry
	httpClient *http.Client
}

func New(reg *registry.Registry) *Protocol {
	return &Protocol{
		reg:        reg,
		httpClient: &http.Client{Timeout: 90 * time.Second},
	}
}

func (p *Protocol) SetHTTPClient(c *http.Client) {
	p.httpClient = c
}

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
		B32:    self.B32,
		Phrase: phrase,
		Hash:   hash,
	}, nil
}

func (p *Protocol) HandleJoin(req *JoinRequest) (*JoinResponse, error) {
	if !p.reg.ConsumeInvite(req.Token) {
		return nil, fmt.Errorf("join: invalid or expired token")
	}
	newPeer := &registry.Peer{
		B32:         req.B32,
		SMBB32:      req.SMBB32,
		Phrase:      req.Phrase,
		PhraseHash:  req.Token,
		Role:        req.Role,
		QuotaBytes:  req.QuotaBytes,
		StoragePath: req.StoragePath,
		Status:      registry.StatusPending,
	}
	if err := p.reg.AddPeer(newPeer); err != nil {
		return nil, fmt.Errorf("join: register peer: %w", err)
	}
	go p.broadcastAnnounce(&AnnounceRequest{
		B32:         req.B32,
		SMBB32:      req.SMBB32,
		Phrase:      req.Phrase,
		PhraseHash:  req.Token,
		Role:        req.Role,
		QuotaBytes:  req.QuotaBytes,
		StoragePath: req.StoragePath,
	}, req.B32)

	self := p.reg.Self()
	return &JoinResponse{
		Peers:   p.reg.Peers(),
		SelfB32: self.B32,
	}, nil
}

func (p *Protocol) HandleAnnounce(req *AnnounceRequest) error {
	if p.reg.HasPeer(req.B32) {
		_ = p.reg.UpdatePeerStatus(req.B32, registry.StatusPending)
		return nil
	}
	return p.reg.AddPeer(&registry.Peer{
		B32:         req.B32,
		SMBB32:      req.SMBB32,
		Phrase:      req.Phrase,
		PhraseHash:  req.PhraseHash,
		Role:        req.Role,
		QuotaBytes:  req.QuotaBytes,
		StoragePath: req.StoragePath,
		Status:      registry.StatusPending,
	})
}

func (p *Protocol) SendJoinRequest(
	targetAPIB32 string,
	phrase words.Phrase,
	role registry.Role,
	quotaBytes int64,
	storagePath string,
) (*JoinResponse, error) {
	self := p.reg.Self()
	// Use the actual B32 from the registry (should be non‑pending by now)
	apiB32 := self.B32
	smbB32 := self.SMBB32
	if apiB32 == "" || apiB32 == "pending" {
		return nil, fmt.Errorf("local node not ready: API B32 not yet resolved")
	}
	if smbB32 == "" || smbB32 == "pending" {
		return nil, fmt.Errorf("local node not ready: SMB B32 not yet resolved")
	}

	req := &JoinRequest{
		Token:       phrase.Hash(),
		B32:         apiB32,
		SMBB32:      smbB32,
		Phrase:      self.Phrase,
		Role:        role,
		QuotaBytes:  quotaBytes,
		StoragePath: storagePath,
	}

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

	// Register every received peer except ourselves (keyed by API B32)
	for _, peer := range jr.Peers {
		if peer.B32 != apiB32 {
			_ = p.reg.AddPeer(peer)
		}
	}
	return &jr, nil
}

func (p *Protocol) broadcastAnnounce(req *AnnounceRequest, excludeB32 string) {
	for _, peer := range p.reg.Peers() {
		if peer.B32 == excludeB32 {
			continue
		}
		url := fmt.Sprintf("http://%s/v1/peer_announce", peer.B32)
		resp, err := p.postJSON(url, req)
		if err == nil {
			resp.Body.Close()
		}
	}
}

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
