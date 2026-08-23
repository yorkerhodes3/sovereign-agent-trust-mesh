// Command satm-broker verifies Agent Mesh Bindings.
//
// The broker is the joint between the two identity systems SATM composes: a
// libp2p PeerID on one side, an ERC-8004 agentId on the other. It accepts a
// signed binding document, runs checks B1..B15, and on success records the
// binding. It does NOT itself approve mesh enrollment -- that stays a separate,
// deliberately manual step (SPECIFICATION.md 6.1).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/binding"
	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/chainrpc"
	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/config"
	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/fetch"
	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/store"
)

// maxRequestBytes caps a submission. Binding documents are a few hundred bytes;
// anything approaching this is not a legitimate request.
const maxRequestBytes = 64 * 1024

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "satm-broker: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath = flag.String("config", "satm-broker.yaml", "path to satm-broker.yaml")
		listenAddr = flag.String("listen", "", "override listen address")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *listenAddr != "" {
		cfg.Listen = *listenAddr
	}

	verifierCfg, err := cfg.VerifierConfig()
	if err != nil {
		return err
	}

	rpcCfg := chainrpc.DefaultConfig(cfg.Chains.Identity.RPCUrls...)
	rpcCfg.Quorum = cfg.Chains.Identity.RPCQuorum
	chain, err := chainrpc.New(rpcCfg)
	if err != nil {
		return err
	}

	fetcher := fetch.New(cfg.FetchConfig())

	// The in-memory store is correct for a single broker instance and is the
	// only implementation with test evidence behind it. internal/pgstore exists
	// for multi-replica deployments but has never been run (see its package
	// doc), so it is deliberately NOT the default.
	nonceStore := store.NewMemory()

	verifier, err := binding.NewVerifier(verifierCfg, chain, fetcher, nonceStore)
	if err != nil {
		return err
	}

	srv := &server{verifier: verifier, store: nonceStore, log: logger, cfg: cfg}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/bindings", srv.handleCreateBinding)
	mux.HandleFunc("GET /v1/bindings/{caid...}", srv.handleGetBinding)
	mux.HandleFunc("GET /healthz", srv.handleHealth)

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("broker listening",
			"addr", cfg.Listen,
			"meshId", cfg.MeshID,
			"trustedRegistries", len(cfg.Binding.TrustedRegistries),
			"rpcEndpoints", len(cfg.Chains.Identity.RPCUrls))
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutdownCtx)
	}
}

type server struct {
	verifier *binding.Verifier
	store    *store.Memory
	log      *slog.Logger
	cfg      *config.Config
}

// createBindingRequest is the wire form of a submission. Byte fields are
// base64-encoded; the document is carried as opaque bytes rather than as nested
// JSON so the broker verifies signatures over EXACTLY the bytes the client
// signed, with no re-serialisation in between.
type createBindingRequest struct {
	Document        []byte `json:"document"`
	PeerPublicKey   []byte `json:"peerPublicKey"`
	PeerSignature   []byte `json:"peerSignature"`
	WalletSignature []byte `json:"walletSignature"`
}

type bindingResponse struct {
	ID             string    `json:"id"`
	CAID           string    `json:"caid"`
	PeerID         string    `json:"peerId"`
	MeshID         string    `json:"meshId"`
	AgentWallet    string    `json:"agentWallet"`
	Owner          string    `json:"owner"`
	Registry       string    `json:"registry"`
	DomainVerified bool      `json:"domainVerified"`
	IssuedAt       time.Time `json:"issuedAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

type errorResponse struct {
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}

func (s *server) handleCreateBinding(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "malformed", "could not read request body")
		return
	}
	if len(body) > maxRequestBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "malformed", "request body too large")
		return
	}

	var req createBindingRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "malformed", "request is not valid JSON")
		return
	}

	result, err := s.verifier.Verify(r.Context(), binding.Input{
		Document:        req.Document,
		PeerPublicKey:   req.PeerPublicKey,
		PeerSignature:   req.PeerSignature,
		WalletSignature: req.WalletSignature,
	})
	if err != nil {
		var vErr *binding.Error
		if errors.As(err, &vErr) {
			// Reason codes are stable and safe to expose: they name WHICH check
			// failed, which an honest client needs, without leaking chain state
			// or internal addresses.
			s.log.Info("binding denied", "reason", string(vErr.Reason), "detail", vErr.Detail)
			writeError(w, http.StatusUnprocessableEntity, string(vErr.Reason), vErr.Detail)
			return
		}
		// An unexpected error is an infrastructure failure, not a verdict on the
		// submission. Reporting it as a denial would misattribute the fault.
		s.log.Error("binding verification failed", "err", err)
		writeError(w, http.StatusServiceUnavailable, "unavailable",
			"verification could not be completed")
		return
	}

	rec := result.Record
	s.log.Info("binding accepted",
		"caid", rec.CAID, "peerId", rec.PeerID, "registry", result.Registry.Tuple)

	writeJSON(w, http.StatusCreated, bindingResponse{
		ID:             rec.ID,
		CAID:           rec.CAID,
		PeerID:         rec.PeerID,
		MeshID:         rec.MeshID,
		AgentWallet:    rec.AgentWallet,
		Owner:          rec.Owner,
		Registry:       result.Registry.Tuple,
		DomainVerified: result.DomainVerified,
		IssuedAt:       rec.IssuedAt,
		ExpiresAt:      rec.ExpiresAt,
	})
}

func (s *server) handleGetBinding(w http.ResponseWriter, r *http.Request) {
	caid := r.PathValue("caid")
	if caid == "" {
		writeError(w, http.StatusBadRequest, "malformed", "caid is required")
		return
	}
	rec, ok := s.store.ActiveByCAID(r.Context(), caid)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "no active binding for that agent")
		return
	}
	writeJSON(w, http.StatusOK, bindingResponse{
		ID:             rec.ID,
		CAID:           rec.CAID,
		PeerID:         rec.PeerID,
		MeshID:         rec.MeshID,
		AgentWallet:    rec.AgentWallet,
		Owner:          rec.Owner,
		DomainVerified: rec.DomainVerified,
		IssuedAt:       rec.IssuedAt,
		ExpiresAt:      rec.ExpiresAt,
	})
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"meshId":  s.cfg.MeshID,
		"chainId": s.cfg.Chains.Identity.ChainID,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, reason, detail string) {
	writeJSON(w, status, errorResponse{Reason: reason, Detail: detail})
}
