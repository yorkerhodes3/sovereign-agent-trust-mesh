// Package fetch implements the SSRF-hardened RegistrationFetcher port.
//
// This component is unusual in that its entire purpose is to be paranoid. It
// fetches a URL that an UNTRUSTED party chose: the agentURI comes from whoever
// registered the agent, and anyone can register an agent. Every request this
// package makes is, in effect, attacker-directed.
//
// Threats TH-8 (SSRF / resource exhaustion) and TH-9 (malicious registration
// file) both live here.
package fetch

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/binding"
)

// Config parameterises the fetcher. DefaultConfig returns the values
// SPECIFICATION.md 4.6/B10 specifies.
type Config struct {
	// AllowedSchemes is the URI scheme allow-list. Anything else is refused
	// before a single packet is sent.
	AllowedSchemes []string

	// MaxBytes caps the response body. Enforced with a limited reader, not by
	// trusting Content-Length, which the attacker controls.
	MaxBytes int64

	// Timeout bounds the WHOLE operation including redirects and body read, so
	// a slow-loris server cannot pin a broker goroutine indefinitely.
	Timeout time.Duration

	// MaxRedirects bounds redirect chains. Every hop is re-validated.
	MaxRedirects int

	// BlockPrivateRanges refuses connections to loopback, link-local, private
	// and CGNAT space. This is what stops an agentURI being used to probe the
	// broker's own network.
	BlockPrivateRanges bool

	// IPFSGateway is prepended to ipfs:// URIs. IPFS is content-addressed, so
	// integrity does not depend on the gateway returning honest bytes -- but the
	// gateway is still an untrusted HTTP endpoint and gets the same treatment.
	IPFSGateway string

	// NegativeCacheTTL suppresses repeat fetches of a URI that just failed, so a
	// dead or hostile URI cannot amplify load through the broker.
	NegativeCacheTTL time.Duration

	// MaxJSONDepth and MaxJSONArray bound structural nesting (TH-9).
	MaxJSONDepth int
	MaxJSONArray int
}

// DefaultConfig returns the specified defaults.
func DefaultConfig() Config {
	return Config{
		AllowedSchemes:     []string{"https", "ipfs", "data"},
		MaxBytes:           256 * 1024,
		Timeout:            5 * time.Second,
		MaxRedirects:       3,
		BlockPrivateRanges: true,
		IPFSGateway:        "https://ipfs.io/ipfs/",
		NegativeCacheTTL:   time.Minute,
		MaxJSONDepth:       32,
		MaxJSONArray:       256,
	}
}

// Fetcher is an SSRF-hardened RegistrationFetcher.
type Fetcher struct {
	cfg    Config
	client *http.Client

	mu       sync.Mutex
	negative map[string]time.Time
	now      func() time.Time
}

var _ binding.RegistrationFetcher = (*Fetcher)(nil)

// New builds a Fetcher.
//
// The transport is constructed here rather than accepted from the caller: the
// DialContext hook below is the ONLY place that reliably blocks private-range
// connections, and letting a caller supply a transport would let them silently
// remove it.
func New(cfg Config) *Fetcher {
	f := &Fetcher{
		cfg:      cfg,
		negative: map[string]time.Time{},
		now:      time.Now,
	}

	dialer := &net.Dialer{Timeout: cfg.Timeout, KeepAlive: 0}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// This runs AFTER DNS resolution and BEFORE the connection is used,
			// which closes the DNS-rebinding hole: validating a hostname up
			// front is useless if the name resolves to a public IP on the first
			// lookup and 127.0.0.1 on the second. Here we see the address
			// actually being dialled.
			if cfg.BlockPrivateRanges {
				host, _, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, fmt.Errorf("malformed dial address %q", addr)
				}
				ip := net.ParseIP(host)
				if ip == nil {
					return nil, fmt.Errorf("dial address %q is not an IP", host)
				}
				if reason := BlockedIP(ip); reason != "" {
					return nil, fmt.Errorf("refusing to connect to %s: %s", ip, reason)
				}
			}
			return dialer.DialContext(ctx, network, addr)
		},
		// Keep the pool small and short-lived. This client talks to arbitrary
		// attacker-chosen hosts, so pooled connections are a liability rather
		// than an optimisation.
		MaxIdleConns:          8,
		IdleConnTimeout:       10 * time.Second,
		TLSHandshakeTimeout:   cfg.Timeout,
		ResponseHeaderTimeout: cfg.Timeout,
		DisableCompression:    true, // no decompression bombs
	}

	f.client = &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > cfg.MaxRedirects {
				return fmt.Errorf("too many redirects (>%d)", cfg.MaxRedirects)
			}
			// Re-validate the scheme on every hop: an https:// URI that
			// redirects to file:// would otherwise escape the allow-list.
			if req.URL.Scheme != "https" && req.URL.Scheme != "http" {
				return fmt.Errorf("redirect to disallowed scheme %q", req.URL.Scheme)
			}
			return nil
		},
	}
	return f
}

// Fetch retrieves and parses a registration file.
func (f *Fetcher) Fetch(ctx context.Context, rawURI string) (*binding.RegistrationFile, error) {
	if f.inNegativeCache(rawURI) {
		return nil, fmt.Errorf("uri %q recently failed; suppressed by negative cache", rawURI)
	}
	file, err := f.fetch(ctx, rawURI)
	if err != nil {
		f.recordFailure(rawURI)
		return nil, err
	}
	return file, nil
}

func (f *Fetcher) fetch(ctx context.Context, rawURI string) (*binding.RegistrationFile, error) {
	u, err := url.Parse(rawURI)
	if err != nil {
		return nil, fmt.Errorf("agentURI is not a valid URI: %w", err)
	}
	if !f.schemeAllowed(u.Scheme) {
		return nil, fmt.Errorf("scheme %q is not allowed (permitted: %s)",
			u.Scheme, strings.Join(f.cfg.AllowedSchemes, ", "))
	}

	ctx, cancel := context.WithTimeout(ctx, f.cfg.Timeout)
	defer cancel()

	var body []byte
	switch u.Scheme {
	case "data":
		body, err = decodeDataURI(rawURI, f.cfg.MaxBytes)
	case "ipfs":
		body, err = f.httpGet(ctx, f.ipfsToHTTP(u))
	default: // https, or http when explicitly allow-listed for a devnet
		body, err = f.httpGet(ctx, rawURI)
	}
	if err != nil {
		return nil, err
	}

	if err := CheckJSONShape(body, f.cfg.MaxJSONDepth, f.cfg.MaxJSONArray); err != nil {
		return nil, fmt.Errorf("registration file rejected: %w", err)
	}
	return binding.ParseRegistrationFile(body)
}

func (f *Fetcher) schemeAllowed(scheme string) bool {
	for _, s := range f.cfg.AllowedSchemes {
		if s == scheme {
			return true
		}
	}
	return false
}

// ipfsToHTTP rewrites ipfs://<cid>[/path] onto the configured gateway.
func (f *Fetcher) ipfsToHTTP(u *url.URL) string {
	cid := u.Host
	rest := strings.TrimPrefix(u.Path, "/")
	if cid == "" {
		cid = rest
		rest = ""
	}
	if rest != "" {
		return f.cfg.IPFSGateway + cid + "/" + rest
	}
	return f.cfg.IPFSGateway + cid
}

func (f *Fetcher) httpGet(ctx context.Context, target string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "satm-broker/0.1 (+registration-file-fetch)")

	resp, err := f.client.Do(req)
	if err != nil {
		// net/http wraps dial errors; unwrap so an operator sees
		// "refusing to connect to 127.0.0.1" rather than a generic failure.
		var urlErr *url.Error
		if errors.As(err, &urlErr) && urlErr.Err != nil {
			return nil, fmt.Errorf("fetch %s: %w", target, urlErr.Err)
		}
		return nil, fmt.Errorf("fetch %s: %w", target, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", target, resp.StatusCode)
	}

	// Read MaxBytes+1 so an over-cap body is DETECTED rather than silently
	// truncated into something that might still parse.
	limited := io.LimitReader(resp.Body, f.cfg.MaxBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", target, err)
	}
	if int64(len(body)) > f.cfg.MaxBytes {
		return nil, fmt.Errorf("registration file exceeds %d bytes", f.cfg.MaxBytes)
	}
	return body, nil
}

// decodeDataURI handles fully on-chain registration files, which ERC-8004
// explicitly permits via base64 data URIs.
func decodeDataURI(raw string, maxBytes int64) ([]byte, error) {
	const prefix = "data:application/json;base64,"
	if !strings.HasPrefix(raw, prefix) {
		return nil, fmt.Errorf("data URI must start with %q", prefix)
	}
	payload := raw[len(prefix):]
	// base64 expands by 4/3, so bound the ENCODED form before decoding rather
	// than allocating first and checking after.
	if int64(len(payload)) > (maxBytes*4)/3+4 {
		return nil, fmt.Errorf("data URI exceeds %d decoded bytes", maxBytes)
	}
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("data URI is not valid base64: %w", err)
	}
	if int64(len(decoded)) > maxBytes {
		return nil, fmt.Errorf("data URI exceeds %d decoded bytes", maxBytes)
	}
	return decoded, nil
}

// ---------------------------------------------------------------- caching --

func (f *Fetcher) inNegativeCache(uri string) bool {
	if f.cfg.NegativeCacheTTL <= 0 {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	until, ok := f.negative[uri]
	if !ok {
		return false
	}
	if f.now().After(until) {
		delete(f.negative, uri)
		return false
	}
	return true
}

func (f *Fetcher) recordFailure(uri string) {
	if f.cfg.NegativeCacheTTL <= 0 {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.negative[uri] = f.now().Add(f.cfg.NegativeCacheTTL)
}
