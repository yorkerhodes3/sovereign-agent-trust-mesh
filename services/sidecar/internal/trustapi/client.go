// Package trustapi is an HTTP client for the broker's Trust API.
//
// The sidecar uses it to resolve a caller's binding during attestation check V5,
// and to resolve a target peer during outbound authorization.
package trustapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mr-tron/base58"

	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/internal/attest"
)

// Config parameterises the client.
type Config struct {
	BaseURL string
	Timeout time.Duration

	// CacheTTL bounds how long a resolved binding may be reused.
	//
	// This is deliberately SHORT. The binding is the revocation point: if an
	// agent is re-bound or revoked, a stale cache entry keeps a superseded
	// sidecar key working for its lifetime, which directly weakens check V6.
	// Caching exists to absorb bursts, not to reduce freshness.
	CacheTTL time.Duration

	MaxResponseBytes int64
}

// DefaultConfig returns usable defaults.
func DefaultConfig(baseURL string) Config {
	return Config{
		BaseURL:          strings.TrimSuffix(baseURL, "/"),
		Timeout:          3 * time.Second,
		CacheTTL:         5 * time.Second,
		MaxResponseBytes: 256 * 1024,
	}
}

// Client resolves bindings from the broker.
type Client struct {
	cfg  Config
	http *http.Client

	mu    sync.Mutex
	cache map[string]cacheEntry
	now   func() time.Time
}

type cacheEntry struct {
	binding *attest.CallerBinding
	expires time.Time
}

var _ attest.TrustAPI = (*Client)(nil)

// New builds a Client.
func New(cfg Config) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("trustapi: baseURL is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = 256 * 1024
	}
	return &Client{
		cfg:   cfg,
		http:  &http.Client{Timeout: cfg.Timeout},
		cache: map[string]cacheEntry{},
		now:   func() time.Time { return time.Now().UTC() },
	}, nil
}

// bindingResponse mirrors the broker's binding JSON.
type bindingResponse struct {
	ID         string `json:"id"`
	CAID       string `json:"caid"`
	PeerID     string `json:"peerId"`
	SidecarKey string `json:"sidecarKey"`
	Active     bool   `json:"active"`
}

// BindingByID implements attest.TrustAPI.
func (c *Client) BindingByID(ctx context.Context, bindingID string) (*attest.CallerBinding, error) {
	if cached, ok := c.fromCache(bindingID); ok {
		return cached, nil
	}

	url := c.cfg.BaseURL + "/v1/bindings/by-id/" + bindingID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("trustapi: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("trustapi: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		// A definitive "no such binding" is a VERDICT, so it is cached like any
		// other answer would be -- but as an error, never as a usable binding.
		return nil, attest.ErrBindingNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("trustapi: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, c.cfg.MaxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("trustapi: read response: %w", err)
	}
	if int64(len(body)) > c.cfg.MaxResponseBytes {
		return nil, fmt.Errorf("trustapi: response exceeds %d bytes", c.cfg.MaxResponseBytes)
	}

	var out bindingResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("trustapi: decode response: %w", err)
	}

	key, err := decodeSidecarKey(out.SidecarKey)
	if err != nil {
		return nil, fmt.Errorf("trustapi: binding %s: %w", bindingID, err)
	}
	if out.ID != bindingID {
		// The broker answered about a different binding than was asked for.
		// Trusting it would attribute one agent's key to another.
		return nil, fmt.Errorf("trustapi: asked for binding %s, got %s", bindingID, out.ID)
	}

	b := &attest.CallerBinding{
		BindingID:  out.ID,
		CAID:       out.CAID,
		PeerID:     out.PeerID,
		SidecarKey: key,
		Active:     out.Active,
	}
	c.store(bindingID, b)
	return b, nil
}

// decodeSidecarKey parses the "ed25519:<base58btc>" form carried in binding
// documents, or a bare base64url key.
func decodeSidecarKey(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("binding has no sidecarKey")
	}
	if rest, ok := strings.CutPrefix(s, "ed25519:"); ok {
		key, err := base58.Decode(rest)
		if err != nil {
			return nil, fmt.Errorf("sidecarKey is not valid base58btc: %w", err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("sidecarKey is %d bytes, expected 32", len(key))
		}
		return key, nil
	}
	key, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("sidecarKey is neither ed25519:<base58btc> nor base64url: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("sidecarKey is %d bytes, expected 32", len(key))
	}
	return key, nil
}

func (c *Client) fromCache(id string) (*attest.CallerBinding, bool) {
	if c.cfg.CacheTTL <= 0 {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.cache[id]
	if !ok || c.now().After(e.expires) {
		delete(c.cache, id)
		return nil, false
	}
	copied := *e.binding
	return &copied, true
}

func (c *Client) store(id string, b *attest.CallerBinding) {
	if c.cfg.CacheTTL <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	copied := *b
	c.cache[id] = cacheEntry{binding: &copied, expires: c.now().Add(c.cfg.CacheTTL)}
}

// Invalidate drops a cached binding, so a revocation can take effect
// immediately rather than at the end of the TTL.
func (c *Client) Invalidate(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.cache, id)
}
