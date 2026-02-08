package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/stainless-api/stainless-proxy/internal/jwe"
	"github.com/stainless-api/stainless-proxy/internal/keystore"
	"github.com/stainless-api/stainless-proxy/internal/revocation"
)

type Handlers struct {
	keyStore *keystore.KeyStore
	denyList *revocation.DenyList
}

func NewHandlers(ks *keystore.KeyStore, dl *revocation.DenyList) *Handlers {
	return &Handlers{keyStore: ks, denyList: dl}
}

func (h *Handlers) JWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(h.keyStore.JWKS())
}

func (h *Handlers) Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"status":"ok"}`)
}

type revokeRequest struct {
	Hash      string `json:"hash"`
	ExpiresAt int64  `json:"expires_at"`
}

func (h *Handlers) Revoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req revokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Hash == "" {
		http.Error(w, `{"error":"hash is required"}`, http.StatusBadRequest)
		return
	}

	expiresAt := time.Unix(req.ExpiresAt, 0)
	if req.ExpiresAt == 0 {
		expiresAt = time.Now().Add(24 * time.Hour)
	}

	h.denyList.Add(req.Hash, expiresAt)
	slog.Info("JWE revoked", "hash", req.Hash, "expires_at", expiresAt)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, `{"status":"revoked"}`)
}

type mintRequest struct {
	ExpDuration  string           `json:"exp_duration"`
	AllowedHosts []string         `json:"allowed_hosts"`
	Credentials  []jwe.Credential `json:"credentials"`
}

type mintResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

func (h *Handlers) Mint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req mintRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if len(req.AllowedHosts) == 0 {
		http.Error(w, `{"error":"allowed_hosts is required"}`, http.StatusBadRequest)
		return
	}
	if len(req.Credentials) == 0 {
		http.Error(w, `{"error":"credentials is required"}`, http.StatusBadRequest)
		return
	}

	duration, err := time.ParseDuration(req.ExpDuration)
	if err != nil {
		http.Error(w, `{"error":"invalid exp_duration"}`, http.StatusBadRequest)
		return
	}

	expiresAt := time.Now().Add(duration)
	payload := jwe.Payload{
		Exp:          expiresAt.Unix(),
		AllowedHosts: req.AllowedHosts,
		Credentials:  req.Credentials,
	}

	primary := h.keyStore.PrimaryKey()
	enc := jwe.NewEncryptor(primary.PublicKey, primary.KID)

	token, err := enc.Encrypt(payload)
	if err != nil {
		slog.Error("minting JWE failed", "error", err)
		http.Error(w, `{"error":"encryption failed"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(mintResponse{
		Token:     token,
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
	})
}
