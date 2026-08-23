package chainrpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/binding"
)

// TestSelectorsMatchKnownValues pins the keccak/selector derivation against
// selectors that are publicly documented and independently verifiable.
//
// If this test drifts, every call this package makes is silently going to the
// wrong function -- so it is checked against constants rather than against the
// implementation's own output.
func TestSelectorsMatchKnownValues(t *testing.T) {
	cases := []struct {
		sig  string
		want string
	}{
		{sigOwnerOf, "6352211e"},          // ERC-721 ownerOf(uint256)
		{sigTokenURI, "c87b56dd"},         // ERC-721 tokenURI(uint256)
		{sigIsValidSignature, "1626ba7e"}, // EIP-1271 isValidSignature(bytes32,bytes)
	}
	for _, tc := range cases {
		got := hex.EncodeToString(selectorFor(tc.sig))
		if got != tc.want {
			t.Errorf("selectorFor(%q) = %s, want %s", tc.sig, got, tc.want)
		}
	}

	// The EIP-1271 magic value is by definition the isValidSignature selector.
	if hex.EncodeToString(erc1271MagicValue[:]) != "1626ba7e" {
		t.Error("erc1271MagicValue does not equal the isValidSignature selector")
	}
}

func TestEncodeUint256Call(t *testing.T) {
	data, err := encodeUint256Call(sigOwnerOf, big.NewInt(42))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	want := "6352211e" + "000000000000000000000000000000000000000000000000000000000000002a"
	if got := hex.EncodeToString(data); got != want {
		t.Fatalf("calldata = %s, want %s", got, want)
	}
}

func TestEncodeUint256CallRejectsBadValues(t *testing.T) {
	if _, err := encodeUint256Call(sigOwnerOf, nil); err == nil {
		t.Error("nil agentID was accepted")
	}
	if _, err := encodeUint256Call(sigOwnerOf, big.NewInt(-1)); err == nil {
		t.Error("negative agentID was accepted")
	}
	tooBig := new(big.Int).Lsh(big.NewInt(1), 256)
	if _, err := encodeUint256Call(sigOwnerOf, tooBig); err == nil {
		t.Error("value overflowing uint256 was accepted")
	}
	// Exactly 2^256-1 must be allowed: it is a legal agent id.
	maxUint := new(big.Int).Sub(tooBig, big.NewInt(1))
	if _, err := encodeUint256Call(sigOwnerOf, maxUint); err != nil {
		t.Errorf("max uint256 was rejected: %v", err)
	}
}

// TestEncodeIsValidSignatureLayout checks the dynamic-argument encoding, which
// is the part of hand-rolled ABI most likely to be subtly wrong.
func TestEncodeIsValidSignatureLayout(t *testing.T) {
	var digest [32]byte
	for i := range digest {
		digest[i] = byte(i + 1)
	}
	sig := make([]byte, 65)
	for i := range sig {
		sig[i] = 0xAB
	}

	data := encodeIsValidSignature(digest, sig)

	// 4 selector + 32 digest + 32 offset + 32 length + 96 padded payload (65 -> 96)
	if len(data) != 4+32+32+32+96 {
		t.Fatalf("calldata length = %d, want %d", len(data), 4+32+32+32+96)
	}
	if hex.EncodeToString(data[:4]) != "1626ba7e" {
		t.Fatalf("selector = %s", hex.EncodeToString(data[:4]))
	}
	if !equalBytes(data[4:36], digest[:]) {
		t.Fatal("digest word incorrect")
	}
	offset := new(big.Int).SetBytes(data[36:68])
	if offset.Int64() != 64 {
		t.Fatalf("dynamic offset = %d, want 64", offset.Int64())
	}
	length := new(big.Int).SetBytes(data[68:100])
	if length.Int64() != 65 {
		t.Fatalf("bytes length = %d, want 65", length.Int64())
	}
	if !equalBytes(data[100:165], sig) {
		t.Fatal("signature payload incorrect")
	}
	for i, b := range data[165:] {
		if b != 0 {
			t.Fatalf("padding byte %d is 0x%02x, want 0x00", i, b)
		}
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestDecodeAddress(t *testing.T) {
	word, _ := hex.DecodeString("000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266")
	got, err := decodeAddress(word)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if hex.EncodeToString(got[:]) != "f39fd6e51aad88f6f4ce6ab8827279cfffb92266" {
		t.Fatalf("address = %s", hex.EncodeToString(got[:]))
	}
}

// TestDecodeAddressRejectsDirtyPadding matters because silently truncating a
// dirty word would let a hostile contract steer the broker to an address of its
// choosing while looking like a normal return.
func TestDecodeAddressRejectsDirtyPadding(t *testing.T) {
	word, _ := hex.DecodeString("00000000000000000000dead" + "f39fd6e51aad88f6f4ce6ab8827279cfffb92266")
	if _, err := decodeAddress(word); err == nil {
		t.Fatal("address word with non-zero padding was accepted")
	}
	if _, err := decodeAddress([]byte{0x01, 0x02}); err == nil {
		t.Fatal("short address word was accepted")
	}
}

func TestDecodeString(t *testing.T) {
	// offset=32, len=11, "hello world" padded to 32 bytes
	payload := "0000000000000000000000000000000000000000000000000000000000000020" +
		"000000000000000000000000000000000000000000000000000000000000000b" +
		"68656c6c6f20776f726c64" + strings.Repeat("0", 42)
	data, _ := hex.DecodeString(payload)

	got, err := decodeString(data, 2048)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != "hello world" {
		t.Fatalf("string = %q", got)
	}
}

// TestDecodeStringRejectsHostileOffsets covers the memory-safety cases: every
// offset and length in the buffer is chosen by the remote node.
func TestDecodeStringRejectsHostileOffsets(t *testing.T) {
	huge := strings.Repeat("f", 64) // offset = 2^256-1

	cases := map[string]string{
		"offset past end": "00000000000000000000000000000000000000000000000000000000000000ff" +
			"0000000000000000000000000000000000000000000000000000000000000001",
		"offset overflows": huge +
			"0000000000000000000000000000000000000000000000000000000000000001",
		"length past end": "0000000000000000000000000000000000000000000000000000000000000020" +
			"00000000000000000000000000000000000000000000000000000000000000ff",
		"length overflows": "0000000000000000000000000000000000000000000000000000000000000020" +
			huge,
	}
	for name, payload := range cases {
		data, err := hex.DecodeString(payload)
		if err != nil {
			t.Fatalf("%s: bad fixture: %v", name, err)
		}
		if _, err := decodeString(data, 2048); err == nil {
			t.Errorf("%s: hostile payload was accepted", name)
		}
	}

	if _, err := decodeString([]byte{0x00}, 2048); err == nil {
		t.Error("truncated buffer was accepted")
	}
}

func TestDecodeStringEnforcesMaxLength(t *testing.T) {
	payload := "0000000000000000000000000000000000000000000000000000000000000020" +
		"0000000000000000000000000000000000000000000000000000000000000040" +
		strings.Repeat("41", 64)
	data, _ := hex.DecodeString(payload)

	if _, err := decodeString(data, 16); err == nil {
		t.Fatal("over-long string was accepted")
	}
	if _, err := decodeString(data, 2048); err != nil {
		t.Fatalf("in-limit string was rejected: %v", err)
	}
}

// ------------------------------------------------------------ fake RPC ----

// rpcStub is a scriptable JSON-RPC server.
type rpcStub struct {
	*httptest.Server
	respond func(method string, params []any) (any, *rpcError)
	calls   atomic.Int64
}

func newRPCStub(t *testing.T, respond func(method string, params []any) (any, *rpcError)) *rpcStub {
	t.Helper()
	s := &rpcStub{respond: respond}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.calls.Add(1)
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		result, rpcErr := s.respond(req.Method, req.Params)
		resp := map[string]any{"jsonrpc": "2.0", "id": req.ID}
		if rpcErr != nil {
			resp["error"] = rpcErr
		} else {
			resp["result"] = result
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(s.Close)
	return s
}

func word(hexStr string) string {
	return strings.Repeat("0", 64-len(hexStr)) + hexStr
}

const testOwner = "f39fd6e51aad88f6f4ce6ab8827279cfffb92266"

var testRegistry = [20]byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}

func TestOwnerOfAgainstStub(t *testing.T) {
	stub := newRPCStub(t, func(method string, params []any) (any, *rpcError) {
		if method != "eth_call" {
			return nil, &rpcError{Code: -32601, Message: "unexpected method " + method}
		}
		return "0x" + word(testOwner), nil
	})

	c, err := New(DefaultConfig(stub.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	owner, err := c.OwnerOf(context.Background(), testRegistry, big.NewInt(42))
	if err != nil {
		t.Fatalf("OwnerOf: %v", err)
	}
	if hex.EncodeToString(owner[:]) != testOwner {
		t.Fatalf("owner = %s", hex.EncodeToString(owner[:]))
	}
}

// TestOwnerOfRevertMapsToAgentNotFound pins the contract the verifier relies on.
func TestOwnerOfRevertMapsToAgentNotFound(t *testing.T) {
	stub := newRPCStub(t, func(string, []any) (any, *rpcError) {
		return nil, &rpcError{Code: 3, Message: "execution reverted"}
	})

	c, _ := New(DefaultConfig(stub.URL))
	_, err := c.OwnerOf(context.Background(), testRegistry, big.NewInt(999))
	if !errors.Is(err, binding.ErrAgentNotFound) {
		t.Fatalf("err = %v, want ErrAgentNotFound", err)
	}
}

// TestOwnerOfTransportErrorIsNotAgentNotFound is the other half of the same
// contract: an unreachable node must NOT look like "this agent does not exist",
// because those two conditions call for opposite responses.
func TestOwnerOfTransportErrorIsNotAgentNotFound(t *testing.T) {
	stub := newRPCStub(t, func(string, []any) (any, *rpcError) { return nil, nil })
	url := stub.URL
	stub.Close()

	c, _ := New(DefaultConfig(url))
	_, err := c.OwnerOf(context.Background(), testRegistry, big.NewInt(42))
	if err == nil {
		t.Fatal("unreachable endpoint returned success")
	}
	if errors.Is(err, binding.ErrAgentNotFound) {
		t.Fatal("transport failure was misreported as ErrAgentNotFound")
	}
}

func TestGetAgentWalletZeroIsNotAnError(t *testing.T) {
	stub := newRPCStub(t, func(string, []any) (any, *rpcError) {
		return "0x" + word(""), nil // unset metadata -> zero address
	})

	c, _ := New(DefaultConfig(stub.URL))
	wallet, err := c.GetAgentWallet(context.Background(), testRegistry, big.NewInt(42))
	if err != nil {
		t.Fatalf("zero agentWallet was treated as an error: %v", err)
	}
	if wallet != ([20]byte{}) {
		t.Fatalf("wallet = %s, want zero", hex.EncodeToString(wallet[:]))
	}
}

func TestAgentURIAgainstStub(t *testing.T) {
	uri := "https://example.com/agent.json"
	payload := word("20") + word(fmt.Sprintf("%x", len(uri))) +
		hex.EncodeToString([]byte(uri)) + strings.Repeat("0", 64-len(uri)*2)

	stub := newRPCStub(t, func(string, []any) (any, *rpcError) {
		return "0x" + payload, nil
	})

	c, _ := New(DefaultConfig(stub.URL))
	got, err := c.AgentURI(context.Background(), testRegistry, big.NewInt(42))
	if err != nil {
		t.Fatalf("AgentURI: %v", err)
	}
	if got != uri {
		t.Fatalf("uri = %q, want %q", got, uri)
	}
}

func TestIsValidERC1271Signature(t *testing.T) {
	t.Run("accepts magic value", func(t *testing.T) {
		stub := newRPCStub(t, func(string, []any) (any, *rpcError) {
			return "0x1626ba7e" + strings.Repeat("0", 56), nil
		})
		c, _ := New(DefaultConfig(stub.URL))
		ok, err := c.IsValidERC1271Signature(context.Background(), testRegistry, [32]byte{}, []byte{0x01})
		if err != nil || !ok {
			t.Fatalf("ok=%v err=%v, want true/nil", ok, err)
		}
	})

	t.Run("rejects wrong magic value", func(t *testing.T) {
		stub := newRPCStub(t, func(string, []any) (any, *rpcError) {
			return "0x" + word("0"), nil
		})
		c, _ := New(DefaultConfig(stub.URL))
		ok, err := c.IsValidERC1271Signature(context.Background(), testRegistry, [32]byte{}, []byte{0x01})
		if err != nil || ok {
			t.Fatalf("ok=%v err=%v, want false/nil", ok, err)
		}
	})

	t.Run("EOA returning empty is a rejection", func(t *testing.T) {
		stub := newRPCStub(t, func(string, []any) (any, *rpcError) { return "0x", nil })
		c, _ := New(DefaultConfig(stub.URL))
		ok, err := c.IsValidERC1271Signature(context.Background(), testRegistry, [32]byte{}, []byte{0x01})
		if err != nil || ok {
			t.Fatalf("ok=%v err=%v, want false/nil", ok, err)
		}
	})

	t.Run("revert is a rejection not a failure", func(t *testing.T) {
		stub := newRPCStub(t, func(string, []any) (any, *rpcError) {
			return nil, &rpcError{Code: 3, Message: "execution reverted"}
		})
		c, _ := New(DefaultConfig(stub.URL))
		ok, err := c.IsValidERC1271Signature(context.Background(), testRegistry, [32]byte{}, []byte{0x01})
		if err != nil || ok {
			t.Fatalf("ok=%v err=%v, want false/nil", ok, err)
		}
	})

	t.Run("transport failure propagates", func(t *testing.T) {
		stub := newRPCStub(t, func(string, []any) (any, *rpcError) { return nil, nil })
		url := stub.URL
		stub.Close()
		c, _ := New(DefaultConfig(url))
		if _, err := c.IsValidERC1271Signature(context.Background(), testRegistry, [32]byte{}, []byte{0x01}); err == nil {
			t.Fatal("unreachable endpoint reported a clean rejection")
		}
	})
}

// ------------------------------------------------------------- quorum -----

// TestQuorumRefusesOnDisagreement is the TH-11 assertion: a single lying RPC
// provider must not be able to forge chain state.
func TestQuorumRefusesOnDisagreement(t *testing.T) {
	honest := newRPCStub(t, func(string, []any) (any, *rpcError) {
		return "0x" + word(testOwner), nil
	})
	liar := newRPCStub(t, func(string, []any) (any, *rpcError) {
		return "0x" + word("dead"), nil
	})

	c, err := New(DefaultConfig(honest.URL, liar.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.OwnerOf(context.Background(), testRegistry, big.NewInt(42))
	if err == nil {
		t.Fatal("disagreeing endpoints produced a result; a single liar can forge state")
	}
	if !strings.Contains(err.Error(), "disagree") {
		t.Fatalf("expected disagreement error, got %v", err)
	}
}

func TestQuorumAgreementSucceeds(t *testing.T) {
	mk := func() *rpcStub {
		return newRPCStub(t, func(string, []any) (any, *rpcError) {
			return "0x" + word(testOwner), nil
		})
	}
	a, b, d := mk(), mk(), mk()

	c, _ := New(DefaultConfig(a.URL, b.URL, d.URL))
	owner, err := c.OwnerOf(context.Background(), testRegistry, big.NewInt(42))
	if err != nil {
		t.Fatalf("OwnerOf: %v", err)
	}
	if hex.EncodeToString(owner[:]) != testOwner {
		t.Fatalf("owner = %s", hex.EncodeToString(owner[:]))
	}
	for i, s := range []*rpcStub{a, b, d} {
		if s.calls.Load() == 0 {
			t.Errorf("endpoint %d was never queried; quorum is not fanning out", i)
		}
	}
}

// TestQuorumToleratesOneDeadEndpoint checks that a threshold below the endpoint
// count keeps working when one provider is down -- availability without giving
// up the anti-forgery property.
func TestQuorumToleratesOneDeadEndpoint(t *testing.T) {
	a := newRPCStub(t, func(string, []any) (any, *rpcError) {
		return "0x" + word(testOwner), nil
	})
	b := newRPCStub(t, func(string, []any) (any, *rpcError) {
		return "0x" + word(testOwner), nil
	})
	dead := newRPCStub(t, func(string, []any) (any, *rpcError) { return nil, nil })
	deadURL := dead.URL
	dead.Close()

	cfg := DefaultConfig(a.URL, b.URL, deadURL)
	cfg.Quorum = 2
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.OwnerOf(context.Background(), testRegistry, big.NewInt(42)); err != nil {
		t.Fatalf("2-of-3 quorum failed with one endpoint down: %v", err)
	}
}

func TestNewValidatesConfig(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("empty endpoint list was accepted")
	}
	cfg := DefaultConfig("http://a", "http://b")
	cfg.Quorum = 3
	if _, err := New(cfg); err == nil {
		t.Error("quorum larger than the endpoint count was accepted")
	}
	cfg.Quorum = -1
	if _, err := New(cfg); err == nil {
		t.Error("negative quorum was accepted")
	}
}

// TestRPCIDMismatchRejected guards against a response being attributed to the
// wrong request, which would mean reading one agent's state as another's.
func TestRPCIDMismatchRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      9999,
			"result":  "0x" + word(testOwner),
		})
	}))
	defer srv.Close()

	c, _ := New(DefaultConfig(srv.URL))
	if _, err := c.OwnerOf(context.Background(), testRegistry, big.NewInt(42)); err == nil {
		t.Fatal("response with a mismatched id was accepted")
	}
}

func TestRPCResponseSizeCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x`))
		chunk := strings.Repeat("a", 4096)
		for i := 0; i < 64; i++ {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
		_, _ = w.Write([]byte(`"}`))
	}))
	defer srv.Close()

	cfg := DefaultConfig(srv.URL)
	cfg.MaxResponseBytes = 1024
	c, _ := New(cfg)

	if _, err := c.OwnerOf(context.Background(), testRegistry, big.NewInt(42)); err == nil {
		t.Fatal("oversized RPC response was accepted")
	}
}

func TestRPCNon200Rejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c, _ := New(DefaultConfig(srv.URL))
	_, err := c.OwnerOf(context.Background(), testRegistry, big.NewInt(42))
	if err == nil {
		t.Fatal("HTTP 429 was accepted")
	}
	if errors.Is(err, binding.ErrAgentNotFound) {
		t.Fatal("rate limiting was misreported as ErrAgentNotFound")
	}
}

// TestCallSendsWellFormedRequest inspects what actually goes on the wire.
func TestCallSendsWellFormedRequest(t *testing.T) {
	var got rpcRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": got.ID, "result": "0x" + word(testOwner),
		})
	}))
	defer srv.Close()

	c, _ := New(DefaultConfig(srv.URL))
	if _, err := c.OwnerOf(context.Background(), testRegistry, big.NewInt(42)); err != nil {
		t.Fatalf("OwnerOf: %v", err)
	}

	if got.Method != "eth_call" {
		t.Fatalf("method = %q, want eth_call", got.Method)
	}
	if len(got.Params) != 2 {
		t.Fatalf("params length = %d, want 2", len(got.Params))
	}
	callObj, ok := got.Params[0].(map[string]any)
	if !ok {
		t.Fatalf("params[0] is %T, want an object", got.Params[0])
	}
	if callObj["to"] != "0x1111111111111111111111111111111111111111" {
		t.Fatalf("to = %v", callObj["to"])
	}
	wantData := "0x6352211e" + word("2a")
	if callObj["data"] != wantData {
		t.Fatalf("data = %v, want %s", callObj["data"], wantData)
	}
	if got.Params[1] != "latest" {
		t.Fatalf("block tag = %v, want latest", got.Params[1])
	}
}
