package daemon

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"junknas/internal/words"
)

type apiServer struct {
	d    *Daemon
	port int
}

func newAPIServer(d *Daemon) *apiServer {
	return &apiServer{d: d, port: 6767}
}

func (s *apiServer) Port() int { return s.port }

func (s *apiServer) WriteLockFile() error {
	data, _ := json.Marshal(map[string]int{"api_port": s.port})
	return os.WriteFile("/tmp/junknas.lock", data, 0o644)
}

func (s *apiServer) Serve() error {
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

func (s *apiServer) handleJoin(w http.ResponseWriter, r *http.Request) {
	var req JoinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	resp, err := s.d.Proto.HandleJoin(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	go s.d.onTopologyChange()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *apiServer) handlePeerAnnounce(w http.ResponseWriter, r *http.Request) {
	var req AnnounceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := s.d.Proto.HandleAnnounce(&req); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	go s.d.onTopologyChange()
	w.WriteHeader(http.StatusOK)
}

func (s *apiServer) handleStatus(w http.ResponseWriter, _ *http.Request) {
	apiB32 := s.d.i2pMgr.APIAddress()
	smbB32 := s.d.i2pMgr.SMBAddress()

	self := s.d.reg.Self()
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
		"peers":         s.d.reg.Peers(),
		"peer_count":    len(s.d.reg.Peers()),
		"storage_peers": len(s.d.reg.StoragePeers()),
		"fuse":          s.d.storage.FuseAvailable(),
	})
}

func (s *apiServer) handleInvite(w http.ResponseWriter, _ *http.Request) {
	inv, err := s.d.Proto.GenerateInvite()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if apiB32 := s.d.i2pMgr.APIAddress(); apiB32 != "" {
		inv.B32 = apiB32
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(inv)
}

type ConnectRequest struct {
	TargetB32   string    `json:"target_b32"`
	Phrase      [3]string `json:"phrase"`
	Role        Role      `json:"role"`
	QuotaBytes  int64     `json:"quota_bytes"`
	StoragePath string    `json:"storage_path"`
}

func (s *apiServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	var req ConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	self := s.d.reg.Self()
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

	if req.StoragePath != "" && req.Role == RoleStorage {
		if err := os.MkdirAll(req.StoragePath, 0o750); err != nil {
			log.Printf("[api] mkdir storage %s: %v", req.StoragePath, err)
		}
	}

	resp, err := s.d.Proto.SendJoinRequest(req.TargetB32, phrase, req.Role, req.QuotaBytes, req.StoragePath)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

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
		if err := s.d.reg.SetSelf(self); err != nil {
			http.Error(w, "join succeeded but failed to update local config: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	go s.d.onTopologyChange()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *apiServer) handlePeers(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.d.reg.Peers())
}

func (s *apiServer) handleTest(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Success \n"))
}
