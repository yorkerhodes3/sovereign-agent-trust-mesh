// Command satm-sidecar is the SATM Trust Sidecar.
//
// It runs next to an agent and answers authorization questions the mesh layer
// cannot: SAM's node-level Datalog can express "is this caller bound and
// tiered?" but not "is this specific transfer within this mandate's remaining
// cap right now?".
//
// This build implements the identity half: inbound Call Attestation
// verification (checks V1..V8) and the split authorize schemas. Mandate
// evaluation arrives with Phase 4; see BACKLOG.md.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
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

	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/internal/attest"
	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/sidecar/internal/trustapi"
)

const maxRequestBytes = 256 * 1024

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "satm-sidecar: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		listenAddr   = flag.String("listen", "127.0.0.1:8082", "listen address")
		brokerURL    = flag.String("broker", "http://127.0.0.1:8081", "broker Trust API base URL")
		meshID       = flag.String("mesh", "", "mesh id (required)")
		controlPlane = flag.String("control-plane", "", "control plane URL (required)")
		selfCAID     = flag.String("self-caid", "", "this agent's CAID (required)")
		selfPeerID   = flag.String("self-peer", "", "this agent's libp2p PeerID (required)")
		selfBinding  = flag.String("self-binding", "", "this agent's current binding id (required)")
		keyPath      = flag.String("sidecar-key", "", "path to the Ed25519 sidecar private key (base64url seed)")
		ttl          = flag.Duration("attestation-ttl", 30*time.Second, "maximum attestation lifetime")
		clockSkew    = flag.Duration("clock-skew", 5*time.Second, "tolerated clock skew")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	trust, err := trustapi.New(trustapi.DefaultConfig(*brokerURL))
	if err != nil {
		return err
	}

	store := attest.NewMemoryNonceStore()

	// Self comes from configuration and this agent's own binding record. It is
	// NEVER read from a request body: a body-supplied self would let a caller
	// nominate which identity it is talking to and thereby satisfy check V2
	// against a target of its own choosing (TH-7a).
	verifier, err := attest.NewVerifier(attest.Config{
		MeshID:       *meshID,
		ControlPlane: *controlPlane,
		Self:         attest.SelfFromBinding(*selfCAID, *selfPeerID, *selfBinding),
		TTL:          *ttl,
		ClockSkew:    *clockSkew,
	}, trust, store)
	if err != nil {
		return err
	}

	var signingKey ed25519.PrivateKey
	if *keyPath != "" {
		signingKey, err = loadSidecarKey(*keyPath)
		if err != nil {
			return err
		}
	}

	srv := &server{
		verifier: verifier,
		trust:    trust,
		store:    store,
		signKey:  signingKey,
		self:     attest.SelfFromBinding(*selfCAID, *selfPeerID, *selfBinding),
		meshID:   *meshID,
		cp:       *controlPlane,
		ttl:      *ttl,
		log:      logger,
	}

	httpSrv := &http.Server{
		Addr:              *listenAddr,
		Handler:           srv.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Expired nonces can never be usefully replayed -- check V7 refuses them
	// first -- so retaining them past expiry grows memory for no benefit.
	purgeCtx, stopPurge := context.WithCancel(context.Background())
	defer stopPurge()
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-purgeCtx.Done():
				return
			case <-t.C:
				if n := store.Purge(); n > 0 {
					logger.Debug("purged expired attestation nonces", "count", n)
				}
			}
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("sidecar listening",
			"addr", *listenAddr, "meshId", *meshID, "selfCaid", *selfCAID, "broker", *brokerURL)
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

func loadSidecarKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read sidecar key: %w", err)
	}
	seed, err := base64.RawURLEncoding.DecodeString(trimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("sidecar key must be a base64url-encoded 32-byte seed: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("sidecar key seed is %d bytes, expected %d", len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\n' || s[start] == '\r' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\n' || s[end-1] == '\r' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

type server struct {
	verifier *attest.Verifier
	trust    *trustapi.Client
	store    *attest.MemoryNonceStore
	signKey  ed25519.PrivateKey
	self     attest.Self
	meshID   string
	cp       string
	ttl      time.Duration
	log      *slog.Logger
}

// authorizeRequest is the split schema from SPECIFICATION.md 6.3.4.
//
// Inbound and outbound answer different questions and therefore take different
// inputs. An earlier draft used ONE schema requiring an attestation in both
// directions, which contradicts the outbound flow: the initiator must be
// authorized BEFORE it mints an attestation, so the attestation cannot be an
// input to its own authorization.
//
// Note the absence of a `self` field. That is deliberate and load-bearing.
type authorizeRequest struct {
	Direction string `json:"direction"` // "inbound" | "outbound"

	Peer struct {
		// Outbound: the broker resolves this. The caller cannot forge it
		// because the caller does not perform the lookup.
		PeerID string `json:"peerId,omitempty"`
		// Inbound: a base64url Call Attestation envelope.
		Attestation string `json:"attestation,omitempty"`
	} `json:"peer"`

	Call struct {
		Service string         `json:"service"`
		Tool    string         `json:"tool"`
		Args    map[string]any `json:"args"`
	} `json:"call"`
}

type authorizeResponse struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`

	// Inbound: the authenticated caller, established by the attestation rather
	// than asserted by the request.
	CallerCAID   string `json:"callerCaid,omitempty"`
	CallerPeerID string `json:"callerPeerId,omitempty"`

	// Outbound: the attestation to attach to the onward MCP call.
	Attestation string `json:"attestation,omitempty"`
}

// routes returns the sidecar's HTTP surface.
//
// Defined once and shared with the tests so the two cannot drift.
func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/authorize", s.handleAuthorize)
	mux.HandleFunc("GET /healthz", s.handleHealth)
	return mux
}

func (s *server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, authorizeResponse{Reason: "malformed", Detail: "could not read body"})
		return
	}
	if len(body) > maxRequestBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, authorizeResponse{Reason: "malformed", Detail: "body too large"})
		return
	}

	// Unknown fields are rejected so a request carrying `self` fails loudly
	// rather than being silently ignored. A caller that thinks it can set its
	// own identity should learn otherwise immediately (TH-7a).
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var req authorizeRequest
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, authorizeResponse{
			Reason: "malformed",
			Detail: "request is not valid JSON for this schema: " + err.Error(),
		})
		return
	}

	switch req.Direction {
	case "inbound":
		s.authorizeInbound(w, r, &req)
	case "outbound":
		s.authorizeOutbound(w, r, &req)
	default:
		writeJSON(w, http.StatusBadRequest, authorizeResponse{
			Reason: "malformed",
			Detail: `direction must be "inbound" or "outbound"`,
		})
	}
}

// authorizeInbound answers "may this caller call me?".
func (s *server) authorizeInbound(w http.ResponseWriter, r *http.Request, req *authorizeRequest) {
	if req.Peer.Attestation == "" {
		writeJSON(w, http.StatusBadRequest, authorizeResponse{
			Reason: "malformed",
			Detail: "inbound authorization requires peer.attestation",
		})
		return
	}
	if req.Peer.PeerID != "" {
		// Accepting a peerId here would reintroduce exactly the vulnerability
		// the attestation exists to close: a self-declared caller identity.
		writeJSON(w, http.StatusBadRequest, authorizeResponse{
			Reason: "malformed",
			Detail: "inbound authorization must not carry peer.peerId; caller identity comes from the attestation",
		})
		return
	}

	env, err := attest.ParseEnvelope(req.Peer.Attestation)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, authorizeResponse{
			Reason: string(attest.ReasonMalformed),
			Detail: err.Error(),
		})
		return
	}

	res, err := s.verifier.Verify(r.Context(), env, attest.Request{
		Service: req.Call.Service,
		Tool:    req.Call.Tool,
		Args:    req.Call.Args,
	})
	if err != nil {
		reason := attest.ReasonOf(err)
		status := http.StatusUnprocessableEntity
		if reason == attest.ReasonTrustAPIUnavailable {
			status = http.StatusServiceUnavailable
		}
		var aErr *attest.Error
		detail := err.Error()
		if errors.As(err, &aErr) {
			detail = aErr.Detail
			s.log.Info("inbound denied", "reason", string(reason), "check", aErr.Check, "detail", detail)
		}
		writeJSON(w, status, authorizeResponse{Reason: string(reason), Detail: detail})
		return
	}

	s.log.Info("inbound allowed",
		"callerCaid", res.Caller.CAID, "service", req.Call.Service, "tool", req.Call.Tool)

	writeJSON(w, http.StatusOK, authorizeResponse{
		Allow:        true,
		CallerCAID:   res.Caller.CAID,
		CallerPeerID: res.Caller.PeerID,
	})
}

// authorizeOutbound answers "may I call this peer?" and, if so, mints the
// attestation for the onward call.
//
// Order is authorize -> mint -> send. The attestation is an OUTPUT here, never
// an input.
func (s *server) authorizeOutbound(w http.ResponseWriter, r *http.Request, req *authorizeRequest) {
	if req.Peer.PeerID == "" {
		writeJSON(w, http.StatusBadRequest, authorizeResponse{
			Reason: "malformed",
			Detail: "outbound authorization requires peer.peerId",
		})
		return
	}
	if req.Peer.Attestation != "" {
		writeJSON(w, http.StatusBadRequest, authorizeResponse{
			Reason: "malformed",
			Detail: "outbound authorization must not carry peer.attestation; it is an output of this call, not an input",
		})
		return
	}
	if s.signKey == nil {
		writeJSON(w, http.StatusServiceUnavailable, authorizeResponse{
			Reason: "sidecar.no_signing_key",
			Detail: "no sidecar key configured; cannot mint attestations",
		})
		return
	}

	// Resolving peerId -> binding requires a broker lookup endpoint that is not
	// implemented yet, so outbound authorization cannot complete. Returning a
	// distinct, honest error is far better than inventing an allow.
	writeJSON(w, http.StatusNotImplemented, authorizeResponse{
		Reason: "sidecar.outbound_not_implemented",
		Detail: "outbound authorization needs the broker's peerId->binding resolution and tier lookup; see BACKLOG.md",
	})
}

func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"meshId":     s.meshID,
		"selfCaid":   s.self.CAID,
		"checks":     attest.DescribeChecks(),
		"noncesHeld": s.store.Len(),
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
