package api

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/junknas/junknas/internal/i2p"
	"github.com/junknas/junknas/internal/join"
	"github.com/junknas/junknas/internal/registry"
	"github.com/junknas/junknas/internal/words"
)

type Server struct {
	reg    *registry.Registry
	proto  *join.Protocol
	i2pMgr *i2p.Manager
	port   int
	onJoin func()
}

func New(reg *registry.Registry, proto *join.Protocol, i2pMgr *i2p.Manager, onJoin func()) (*Server, error) {
	return &Server{
		reg:    reg,
		proto:  proto,
		i2pMgr: i2pMgr,
		port:   6767,
		onJoin: onJoin,
	}, nil
}

func (s *Server) Port() int { return s.port }

func (s *Server) WriteLockFile() error {
	data, _ := json.Marshal(map[string]int{"api_port": s.port})
	return os.WriteFile("/tmp/junknas.lock", data, 0o644)
}

func (s *Server) Serve() error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/join", s.handleJoin)
	mux.HandleFunc("POST /v1/peer_announce", s.handlePeerAnnounce)
	mux.HandleFunc("GET /v1/status", s.handleStatus)
	mux.HandleFunc("GET /v1/invite", s.handleInvite)
	mux.HandleFunc("POST /v1/connect", s.handleConnect)
	mux.HandleFunc("GET /v1/peers", s.handlePeers)
	mux.HandleFunc("GET /v1/test", s.handleTest)
	srv := &http.Server{
		Addr:         ":6767",
		Handler:      mux,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
	}
	srv.SetKeepAlivesEnabled(false)
	return srv.ListenAndServe()
}

func (s *Server) handleJoin(w http.ResponseWriter, r *http.Request) {
	var req join.JoinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	resp, err := s.proto.HandleJoin(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if s.onJoin != nil {
		go s.onJoin()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handlePeerAnnounce(w http.ResponseWriter, r *http.Request) {
	var req join.AnnounceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := s.proto.HandleAnnounce(&req); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if s.onJoin != nil {
		go s.onJoin()
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	if s.i2pMgr == nil {
		http.Error(w, "i2p manager not initialized", http.StatusInternalServerError)
		return
	}

	apiB32 := s.i2pMgr.APIAddress()
	smbB32 := s.i2pMgr.SMBAddress()

	self := s.reg.Self()
	if self == nil {
		http.Error(w, "self not yet initialized", http.StatusServiceUnavailable)
		return
	}

	selfView := *self
	if apiB32 != "" {
		selfView.B32 = apiB32
	}
	if smbB32 != "" {
		selfView.SMBB32 = smbB32
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"self":          selfView,
		"peers":         s.reg.Peers(),
		"peer_count":    len(s.reg.Peers()),
		"storage_peers": len(s.reg.StoragePeers()),
	})
}

func (s *Server) handleInvite(w http.ResponseWriter, _ *http.Request) {
	inv, err := s.proto.GenerateInvite()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if s.i2pMgr != nil {
		if apiB32 := s.i2pMgr.APIAddress(); apiB32 != "" {
			inv.B32 = apiB32
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(inv)
}

type ConnectRequest struct {
	TargetB32   string        `json:"target_b32"`
	Phrase      [3]string     `json:"phrase"`
	Role        registry.Role `json:"role"`
	QuotaBytes  int64         `json:"quota_bytes"`
	StoragePath string        `json:"storage_path"`
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	var req ConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Ensure this node is ready to join (B32 addresses already known).
	self := s.reg.Self()
	if self == nil {
		http.Error(w, "self not initialized", http.StatusServiceUnavailable)
		return
	}
	if self.B32 == "pending" || self.SMBB32 == "pending" {
		http.Error(w, "node still bootstrapping I2P, please wait a few seconds", http.StatusServiceUnavailable)
		return
	}

	phrase, err := words.FromSlice(req.Phrase[:])
	if err != nil {
		http.Error(w, "invalid phrase: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Create the storage directory now so it exists before SMB tries to use it.
	if req.StoragePath != "" && req.Role == registry.RoleStorage {
		if err := os.MkdirAll(req.StoragePath, 0o750); err != nil {
			log.Printf("[api] mkdir storage %s: %v", req.StoragePath, err)
			// Non-fatal: log but continue — SMB manager will also try.
		}
	}

	// Synchronously perform the join request over I2P (may take tens of seconds).
	resp, err := s.proto.SendJoinRequest(req.TargetB32, phrase, req.Role, req.QuotaBytes, req.StoragePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// After successful join, update our own self record with the chosen quota,
	// storage path, and role.
	updated := false
	if req.QuotaBytes > 0 && self.QuotaBytes != req.QuotaBytes {
		self.QuotaBytes = req.QuotaBytes
		updated = true
	}
	if req.StoragePath != "" && self.StoragePath != req.StoragePath {
		self.StoragePath = req.StoragePath
		updated = true
	}
	if req.Role != self.Role {
		self.Role = req.Role
		updated = true
	}
	if updated {
		if err := s.reg.SetSelf(self); err != nil {
			http.Error(w, "join succeeded but failed to update local config: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Always trigger a topology rebuild after a successful join — new peers
	// were added to the registry and tunnels need to be established for them,
	// regardless of whether our own role changed.
	if s.onJoin != nil {
		go s.onJoin()
	}

	// Return the peer list that the joining node received.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handlePeers(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.reg.Peers())
}

func (s *Server) handleTest(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Success \n"))
}
