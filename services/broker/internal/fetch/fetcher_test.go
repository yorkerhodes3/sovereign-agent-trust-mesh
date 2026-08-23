package fetch

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// validFile is a minimal ERC-8004 registration file that ParseRegistrationFile
// accepts, so tests can isolate the FETCH policy from parse failures.
const validFile = `{
  "type": "https://eips.ethereum.org/EIPS/eip-8004#registration-v1",
  "name": "test-agent",
  "description": "fixture",
  "active": true,
  "registrations": [
    {"agentId": "42", "agentRegistry": "eip155:31337:0x1111111111111111111111111111111111111111"}
  ]
}`

func testConfig() Config {
	c := DefaultConfig()
	// httptest servers are plain HTTP on loopback. Allowing the scheme lets us
	// exercise the real transport; private-range blocking is disabled only in
	// the tests that are not about that policy, and is asserted directly in the
	// tests that are.
	c.AllowedSchemes = []string{"http", "https", "ipfs", "data"}
	c.BlockPrivateRanges = false
	c.NegativeCacheTTL = 0
	c.Timeout = 2 * time.Second
	return c
}

func TestFetchHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(validFile))
	}))
	defer srv.Close()

	f := New(testConfig())
	file, err := f.Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if file.Name != "test-agent" {
		t.Fatalf("name = %q, want test-agent", file.Name)
	}
	if !file.HasRegistration("eip155:31337:0x1111111111111111111111111111111111111111", "42") {
		t.Fatal("registration tuple not recognised")
	}
}

func TestFetchRejectsDisallowedScheme(t *testing.T) {
	f := New(testConfig())
	for _, uri := range []string{
		"file:///etc/passwd",
		"ftp://example.com/agent.json",
		"gopher://example.com/",
	} {
		if _, err := f.Fetch(context.Background(), uri); err == nil {
			t.Fatalf("scheme in %q was accepted", uri)
		} else if !strings.Contains(err.Error(), "not allowed") {
			t.Fatalf("uri %q: unexpected error %v", uri, err)
		}
	}
}

// TestFetchRefusesPrivateRanges is the core SSRF assertion: with the policy on,
// a loopback target must be refused at DIAL time.
func TestFetchRefusesPrivateRanges(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(validFile))
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.BlockPrivateRanges = true
	f := New(cfg)

	_, err := f.Fetch(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("loopback fetch succeeded; SSRF guard is not engaged")
	}
	if !strings.Contains(err.Error(), "refusing to connect") {
		t.Fatalf("expected dial refusal, got %v", err)
	}
}

// TestFetchRefusesRedirectToLoopback covers the case hostname validation alone
// would miss: a public URL that redirects inward.
func TestFetchRefusesRedirectToLoopback(t *testing.T) {
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"secret":"internal-only"}`))
	}))
	defer internal.Close()

	var redirector *httptest.Server
	redirector = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL, http.StatusFound)
	}))
	defer redirector.Close()
	_ = redirector

	cfg := testConfig()
	cfg.BlockPrivateRanges = true
	f := New(cfg)

	if _, err := f.Fetch(context.Background(), redirector.URL); err == nil {
		t.Fatal("redirect into loopback was followed")
	}
}

func TestFetchEnforcesRedirectLimit(t *testing.T) {
	var srv *httptest.Server
	hops := 0
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops++
		http.Redirect(w, r, srv.URL+"/next", http.StatusFound)
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.MaxRedirects = 2
	f := New(cfg)

	_, err := f.Fetch(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("infinite redirect chain was followed to completion")
	}
	if !strings.Contains(err.Error(), "too many redirects") {
		t.Fatalf("expected redirect-limit error, got %v", err)
	}
}

func TestFetchRejectsRedirectToDisallowedScheme(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "file:///etc/passwd", http.StatusFound)
	}))
	defer srv.Close()

	f := New(testConfig())
	_, err := f.Fetch(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("redirect to file:// was followed")
	}
	if !strings.Contains(err.Error(), "disallowed scheme") {
		t.Fatalf("expected scheme refusal, got %v", err)
	}
}

// TestFetchCapsBodySize proves the cap is enforced on bytes actually read.
//
// The server uses chunked encoding (no Content-Length), which is the case that
// matters: with no declared size the client cannot pre-emptively refuse, so only
// the limited reader stands between the broker and an unbounded allocation.
func TestFetchCapsBodySize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		chunk := strings.Repeat("A", 4096)
		for i := 0; i < 64; i++ {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.MaxBytes = 1024
	f := New(cfg)

	_, err := f.Fetch(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("oversized body was accepted")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected size-cap error, got %v", err)
	}
}

// TestFetchIgnoresContentLengthHeader pins that the cap is applied to bytes
// actually read rather than to a header value, so a declared length can never
// talk the fetcher into accepting an over-cap body.
func TestFetchIgnoresContentLengthHeader(t *testing.T) {
	body := strings.Repeat("A", 8192)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.MaxBytes = 1024
	f := New(cfg)

	if _, err := f.Fetch(context.Background(), srv.URL); err == nil {
		t.Fatal("oversized body was accepted")
	}
}

func TestFetchRejectsNon200(t *testing.T) {
	for _, code := range []int{204, 400, 403, 404, 500, 503} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		f := New(testConfig())
		_, err := f.Fetch(context.Background(), srv.URL)
		srv.Close()
		if err == nil {
			t.Fatalf("HTTP %d was accepted", code)
		}
		if !strings.Contains(err.Error(), fmt.Sprintf("HTTP %d", code)) {
			t.Fatalf("HTTP %d: unexpected error %v", code, err)
		}
	}
}

func TestFetchRejectsWrongType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"type":"something-else","name":"x"}`))
	}))
	defer srv.Close()

	f := New(testConfig())
	if _, err := f.Fetch(context.Background(), srv.URL); err == nil {
		t.Fatal("file with wrong type was accepted")
	}
}

func TestFetchHonoursContextCancellation(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer func() { close(release); srv.Close() }()

	cfg := testConfig()
	cfg.Timeout = 30 * time.Second // ensure the CONTEXT is what stops us
	f := New(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := f.Fetch(ctx, srv.URL); err == nil {
		t.Fatal("hung request returned successfully")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("cancellation took %v; context is not plumbed through", elapsed)
	}
}

func TestFetchTimesOut(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer func() { close(release); srv.Close() }()

	cfg := testConfig()
	cfg.Timeout = 200 * time.Millisecond
	f := New(cfg)

	start := time.Now()
	if _, err := f.Fetch(context.Background(), srv.URL); err == nil {
		t.Fatal("hung request returned successfully")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("timeout took %v, want ~200ms", elapsed)
	}
}

func TestFetchDataURI(t *testing.T) {
	uri := "data:application/json;base64," + base64.StdEncoding.EncodeToString([]byte(validFile))
	f := New(testConfig())
	file, err := f.Fetch(context.Background(), uri)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if file.Name != "test-agent" {
		t.Fatalf("name = %q", file.Name)
	}
}

func TestFetchDataURIRejectsOversize(t *testing.T) {
	big := strings.Repeat("A", 8192)
	uri := "data:application/json;base64," + base64.StdEncoding.EncodeToString([]byte(big))

	cfg := testConfig()
	cfg.MaxBytes = 1024
	f := New(cfg)

	if _, err := f.Fetch(context.Background(), uri); err == nil {
		t.Fatal("oversized data URI was accepted")
	}
}

func TestFetchDataURIRejectsBadEncoding(t *testing.T) {
	f := New(testConfig())
	for _, uri := range []string{
		"data:application/json;base64,!!!!not-base64!!!!",
		"data:text/plain,hello",                           // wrong media type / not base64
		"data:application/json;charset=utf-8;base64,e30=", // unexpected parameter
	} {
		if _, err := f.Fetch(context.Background(), uri); err == nil {
			t.Fatalf("data URI %q was accepted", uri)
		}
	}
}

func TestNegativeCacheSuppressesRepeatFetches(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.NegativeCacheTTL = time.Minute
	f := New(cfg)

	for i := 0; i < 5; i++ {
		if _, err := f.Fetch(context.Background(), srv.URL); err == nil {
			t.Fatal("failing URI returned success")
		}
	}
	if hits != 1 {
		t.Fatalf("origin received %d requests, want 1 (negative cache not suppressing)", hits)
	}
}

func TestNegativeCacheExpires(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.NegativeCacheTTL = time.Minute
	f := New(cfg)

	now := time.Now()
	f.now = func() time.Time { return now }

	if _, err := f.Fetch(context.Background(), srv.URL); err == nil {
		t.Fatal("expected failure")
	}
	now = now.Add(2 * time.Minute) // advance past the TTL
	if _, err := f.Fetch(context.Background(), srv.URL); err == nil {
		t.Fatal("expected failure")
	}
	if hits != 2 {
		t.Fatalf("origin received %d requests, want 2 (cache did not expire)", hits)
	}
}

func TestIPFSURIRewriting(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(validFile))
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.IPFSGateway = srv.URL + "/ipfs/"
	f := New(cfg)

	if _, err := f.Fetch(context.Background(), "ipfs://bafyfixture"); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if gotPath != "/ipfs/bafyfixture" {
		t.Fatalf("gateway path = %q, want /ipfs/bafyfixture", gotPath)
	}

	if _, err := f.Fetch(context.Background(), "ipfs://bafyfixture/agent.json"); err != nil {
		t.Fatalf("Fetch with path: %v", err)
	}
	if gotPath != "/ipfs/bafyfixture/agent.json" {
		t.Fatalf("gateway path = %q, want /ipfs/bafyfixture/agent.json", gotPath)
	}
}

func TestFetchRejectsMalformedURI(t *testing.T) {
	f := New(testConfig())
	if _, err := f.Fetch(context.Background(), "ht!tp://%%%"); err == nil {
		t.Fatal("malformed URI was accepted")
	}
}

// -------------------------------------------------------------- IP policy --

func TestBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1",              // loopback
		"127.1.2.3",              // all of 127/8
		"10.0.0.1",               // RFC 1918
		"172.16.5.4",             // RFC 1918
		"192.168.1.1",            // RFC 1918
		"169.254.169.254",        // cloud instance metadata -- the crown jewel
		"100.64.0.1",             // CGNAT
		"0.0.0.0",                // this-network
		"224.0.0.1",              // multicast
		"255.255.255.255",        // broadcast
		"::1",                    // IPv6 loopback
		"fe80::1",                // IPv6 link-local
		"fd00::1",                // IPv6 ULA
		"::ffff:127.0.0.1",       // IPv4-mapped loopback: the classic bypass
		"::ffff:169.254.169.254", // IPv4-mapped metadata
	}
	for _, s := range blocked {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test fixture %q is not a valid IP", s)
		}
		if reason := BlockedIP(ip); reason == "" {
			t.Errorf("BlockedIP(%s) = allowed, want blocked", s)
		}
	}

	allowed := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1111"}
	for _, s := range allowed {
		ip := net.ParseIP(s)
		if reason := BlockedIP(ip); reason != "" {
			t.Errorf("BlockedIP(%s) = blocked (%s), want allowed", s, reason)
		}
	}

	if BlockedIP(nil) == "" {
		t.Error("BlockedIP(nil) must be blocked")
	}
}

// ------------------------------------------------------------ JSON shape --

func TestCheckJSONShapeDepth(t *testing.T) {
	// 40 KB of "[[[[..." is trivially under any byte cap yet can exhaust the
	// stack during decoding. This is exactly the TH-9 payload.
	deep := strings.Repeat("[", 5000) + strings.Repeat("]", 5000)
	if err := CheckJSONShape([]byte(deep), 32, 256); err == nil {
		t.Fatal("deeply nested JSON was accepted")
	} else if !strings.Contains(err.Error(), "nesting") {
		t.Fatalf("expected nesting error, got %v", err)
	}

	ok := strings.Repeat("[", 10) + strings.Repeat("]", 10)
	if err := CheckJSONShape([]byte(ok), 32, 256); err != nil {
		t.Fatalf("depth-10 document rejected: %v", err)
	}
}

func TestCheckJSONShapeArrayLength(t *testing.T) {
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < 1000; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString("1")
	}
	b.WriteString("]")

	if err := CheckJSONShape([]byte(b.String()), 32, 256); err == nil {
		t.Fatal("over-long array was accepted")
	} else if !strings.Contains(err.Error(), "array") {
		t.Fatalf("expected array error, got %v", err)
	}
}

// TestCheckJSONShapeArrayAccounting pins the subtle case: values nested inside
// an object inside an array must not be charged to the enclosing array.
func TestCheckJSONShapeArrayAccounting(t *testing.T) {
	// One array element, whose object has many members.
	var b strings.Builder
	b.WriteString(`[{`)
	for i := 0; i < 100; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"k%d":%d`, i, i)
	}
	b.WriteString(`}]`)

	if err := CheckJSONShape([]byte(b.String()), 32, 5); err != nil {
		t.Fatalf("object members were miscounted as array elements: %v", err)
	}

	// Sibling arrays must be counted independently, not cumulatively.
	siblings := `{"a":[1,2,3],"b":[1,2,3],"c":[1,2,3]}`
	if err := CheckJSONShape([]byte(siblings), 32, 3); err != nil {
		t.Fatalf("sibling arrays were counted cumulatively: %v", err)
	}

	// Nested containers DO count as elements of their parent array.
	nested := `[[1],[2],[3],[4]]`
	if err := CheckJSONShape([]byte(nested), 32, 3); err == nil {
		t.Fatal("nested containers were not counted as array elements")
	}
}

func TestCheckJSONShapeMalformed(t *testing.T) {
	for _, s := range []string{`{`, `[1,2`, `{"a":}`, `nope`, ``} {
		if err := CheckJSONShape([]byte(s), 32, 256); err == nil {
			t.Errorf("malformed JSON %q was accepted", s)
		}
	}
}

func TestCheckJSONShapeAcceptsRealRegistrationFile(t *testing.T) {
	if err := CheckJSONShape([]byte(validFile), 32, 256); err != nil {
		t.Fatalf("a legitimate registration file was rejected: %v", err)
	}
}
