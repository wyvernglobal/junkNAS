package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/junknas/junknas/internal/join"
	"github.com/junknas/junknas/internal/registry"
	"github.com/junknas/junknas/internal/words"
)

type Server struct {
	reg      *registry.Registry
	proto    *join.Protocol
	port     int
	listener net.Listener
	onJoin   func()
}

func New(reg *registry.Registry, proto *join.Protocol, onJoin func()) (*Server, error) {
	l, err := net.Listen("tcp", "127.0.0.1:36789")
	if err != nil {
		return nil, fmt.Errorf("api: listen: %w", err)
	}
	return &Server{
		reg:      reg,
		proto:    proto,
		port:     l.Addr().(*net.TCPAddr).Port,
		listener: l,
		onJoin:   onJoin,
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
	return (&http.Server{
		Handler:      mux,
		ReadTimeout:  300 * time.Second,
		WriteTimeout: 300 * time.Second,
	}).Serve(s.listener)
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
	writeJSON(w, resp)
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
	writeJSON(w, map[string]any{
		"self":          s.reg.Self(),
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
	writeJSON(w, inv)
}

type ConnectRequest struct {
	TargetB32  string        `json:"target_b32"`
	Phrase     [3]string     `json:"phrase"`
	Role       registry.Role `json:"role"`
	QuotaBytes int64         `json:"quota_bytes"`
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	var req ConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	phrase, err := words.FromSlice(req.Phrase[:])
	if err != nil {
		http.Error(w, "invalid phrase: "+err.Error(), http.StatusBadRequest)
		return
	}
	go func() {
		if _, err := s.proto.SendJoinRequest(req.TargetB32, phrase, req.Role, req.QuotaBytes); err != nil {
			return
		}
		if s.onJoin != nil {
			s.onJoin()
		}
	}()
	writeJSON(w, map[string]string{"status": "joining"})
}

func (s *Server) handlePeers(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.reg.Peers())
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
