package chainrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/binding"
)

// Config parameterises the chain client.
type Config struct {
	// Endpoints are JSON-RPC URLs. More than one enables quorum reads (TH-11):
	// a single RPC provider that lies about ownerOf or getAgentWallet can
	// otherwise forge an entire binding.
	Endpoints []string

	// Quorum is how many endpoints must agree. Zero means "all of them".
	Quorum int

	// Timeout bounds a single RPC round trip.
	Timeout time.Duration

	// MaxResponseBytes caps an RPC response body.
	MaxResponseBytes int64

	// MaxURILength caps a decoded tokenURI, which is attacker-controlled.
	MaxURILength int

	// BlockTag selects the block to read at. "latest" is correct for admission
	// checks: SATM wants the CURRENT state, and reorg handling for trust
	// promotion lives in the indexer (SPECIFICATION.md 13, TH-10), not here.
	BlockTag string
}

// DefaultConfig returns usable defaults for a single-endpoint devnet.
func DefaultConfig(endpoints ...string) Config {
	return Config{
		Endpoints:        endpoints,
		Quorum:           0,
		Timeout:          5 * time.Second,
		MaxResponseBytes: 1 << 20,
		MaxURILength:     2048,
		BlockTag:         "latest",
	}
}

// Client is a JSON-RPC implementation of binding.ChainClient.
type Client struct {
	cfg    Config
	http   *http.Client
	nextID atomic.Uint64
}

var _ binding.ChainClient = (*Client)(nil)

// New validates the configuration and builds a Client.
func New(cfg Config) (*Client, error) {
	if len(cfg.Endpoints) == 0 {
		return nil, fmt.Errorf("chainrpc: at least one RPC endpoint is required")
	}
	if cfg.Quorum == 0 {
		cfg.Quorum = len(cfg.Endpoints)
	}
	if cfg.Quorum < 1 || cfg.Quorum > len(cfg.Endpoints) {
		return nil, fmt.Errorf("chainrpc: quorum %d is not in 1..%d", cfg.Quorum, len(cfg.Endpoints))
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = 1 << 20
	}
	if cfg.BlockTag == "" {
		cfg.BlockTag = "latest"
	}
	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: cfg.Timeout},
	}, nil
}

// ------------------------------------------------------------ ChainClient --

// OwnerOf returns the ERC-721 owner of an agent token.
func (c *Client) OwnerOf(ctx context.Context, registry [20]byte, agentID *big.Int) ([20]byte, error) {
	var zero [20]byte
	data, err := encodeUint256Call(sigOwnerOf, agentID)
	if err != nil {
		return zero, err
	}
	out, err := c.call(ctx, registry, data)
	if err != nil {
		// ERC-721 reverts with ERC721NonexistentToken for an unminted id, so a
		// revert here means precisely "no such agent" -- which is the contract
		// binding.ChainClient documents for this method.
		return zero, asAgentNotFound(err)
	}
	return decodeAddress(out)
}

// GetAgentWallet returns the reserved ERC-8004 `agentWallet` metadata value.
//
// The vendored registry returns address(bytes20(walletData)), which is the zero
// address when the key is unset -- including after an ERC-721 transfer, since
// the new owner has not yet re-attested a wallet. The verifier treats the zero
// address as "no wallet bound" (SPECIFICATION.md 7.3.2, TH-5), so this method
// deliberately does NOT translate zero into an error.
func (c *Client) GetAgentWallet(ctx context.Context, registry [20]byte, agentID *big.Int) ([20]byte, error) {
	var zero [20]byte
	data, err := encodeUint256Call(sigGetAgentWallet, agentID)
	if err != nil {
		return zero, err
	}
	out, err := c.call(ctx, registry, data)
	if err != nil {
		return zero, err
	}
	return decodeAddress(out)
}

// AgentURI returns tokenURI for an agent.
func (c *Client) AgentURI(ctx context.Context, registry [20]byte, agentID *big.Int) (string, error) {
	data, err := encodeUint256Call(sigTokenURI, agentID)
	if err != nil {
		return "", err
	}
	out, err := c.call(ctx, registry, data)
	if err != nil {
		return "", asAgentNotFound(err)
	}
	return decodeString(out, c.cfg.MaxURILength)
}

// IsValidERC1271Signature staticcalls isValidSignature on a contract wallet.
//
// A revert means "not a contract wallet, or it rejected the signature", which is
// a NEGATIVE result rather than an infrastructure failure -- so it returns
// (false, nil). Any other transport error propagates, because failing closed
// requires distinguishing "the wallet said no" from "we could not ask".
func (c *Client) IsValidERC1271Signature(ctx context.Context, wallet [20]byte, digest [32]byte, sig []byte) (bool, error) {
	data := encodeIsValidSignature(digest, sig)
	out, err := c.call(ctx, wallet, data)
	if err != nil {
		if isRevert(err) {
			return false, nil
		}
		return false, err
	}
	if len(out) < 32 {
		// An EOA has no code, so eth_call succeeds and returns empty. That is a
		// rejection, not a malformed response.
		return false, nil
	}
	got, err := decodeBytes4(out[:32])
	if err != nil {
		return false, err
	}
	return got == erc1271MagicValue, nil
}

// ------------------------------------------------------------------ calls --

// call performs eth_call across the endpoint set and enforces the quorum.
func (c *Client) call(ctx context.Context, to [20]byte, data []byte) ([]byte, error) {
	params := []any{
		map[string]string{"to": addressHex(to), "data": hexEncode(data)},
		c.cfg.BlockTag,
	}
	return c.quorumCall(ctx, "eth_call", params)
}

type endpointResult struct {
	endpoint string
	raw      []byte
	err      error
}

// quorumCall fans a request out to every endpoint and requires cfg.Quorum of
// them to return byte-identical results.
//
// Disagreement is reported as an error rather than resolved by majority vote or
// first-response-wins: for reads that gate admission, "my providers disagree
// about who owns this agent" is exactly the situation in which proceeding is
// unsafe (SPECIFICATION.md 14.2, degraded mode).
func (c *Client) quorumCall(ctx context.Context, method string, params []any) ([]byte, error) {
	results := make([]endpointResult, len(c.cfg.Endpoints))
	var wg sync.WaitGroup
	for i, ep := range c.cfg.Endpoints {
		wg.Add(1)
		go func(i int, ep string) {
			defer wg.Done()
			raw, err := c.rpc(ctx, ep, method, params)
			results[i] = endpointResult{endpoint: ep, raw: raw, err: err}
		}(i, ep)
	}
	wg.Wait()

	// A revert is a consensus answer, not a failure: if any endpoint reports one
	// it means the call genuinely reverted on-chain, so surface it immediately.
	for _, r := range results {
		if r.err != nil && isRevert(r.err) {
			return nil, r.err
		}
	}

	tally := map[string]int{}
	byDigest := map[string][]byte{}
	var errs []string
	for _, r := range results {
		if r.err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", r.endpoint, r.err))
			continue
		}
		key := string(r.raw)
		tally[key]++
		byDigest[key] = r.raw
	}

	// Deterministic iteration so the reported error is stable across runs.
	keys := make([]string, 0, len(tally))
	for k := range tally {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		if tally[k] >= c.cfg.Quorum {
			return byDigest[k], nil
		}
	}

	if len(tally) > 1 {
		return nil, fmt.Errorf("chainrpc: endpoints disagree on %s (%d distinct results, quorum %d of %d); "+
			"refusing to proceed", method, len(tally), c.cfg.Quorum, len(c.cfg.Endpoints))
	}
	return nil, fmt.Errorf("chainrpc: %s did not reach quorum %d of %d: %s",
		method, c.cfg.Quorum, len(c.cfg.Endpoints), strings.Join(errs, "; "))
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      uint64 `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *rpcError) Error() string {
	return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message)
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      uint64          `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
}

func (c *Client) rpc(ctx context.Context, endpoint, method string, params []any) ([]byte, error) {
	id := c.nextID.Add(1)
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params})
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from RPC endpoint", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, c.cfg.MaxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if int64(len(raw)) > c.cfg.MaxResponseBytes {
		return nil, fmt.Errorf("RPC response exceeds %d bytes", c.cfg.MaxResponseBytes)
	}

	var out rpcResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if out.Error != nil {
		return nil, out.Error
	}
	if out.ID != id {
		// Guards against a response being matched to the wrong request, which
		// would silently attribute one agent's state to another.
		return nil, fmt.Errorf("RPC id mismatch: sent %d, got %d", id, out.ID)
	}

	var hexResult string
	if err := json.Unmarshal(out.Result, &hexResult); err != nil {
		return nil, fmt.Errorf("result is not a hex string: %w", err)
	}
	return hexDecode(hexResult)
}

// isRevert reports whether an error is an on-chain revert rather than a
// transport or availability problem.
func isRevert(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "execution reverted") ||
		strings.Contains(msg, "revert") ||
		strings.Contains(msg, "invalid opcode") ||
		strings.Contains(msg, "out of gas")
}

// asAgentNotFound converts a revert from an identity-registry read into
// binding.ErrAgentNotFound, which is what the verifier's B7 check expects.
func asAgentNotFound(err error) error {
	if isRevert(err) {
		return binding.ErrAgentNotFound
	}
	return err
}
