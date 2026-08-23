//go:build integration

// Package chainrpc live tests run against a real devnet.
//
// Run with:
//
//	anvil --port 8545 &
//	forge script script/DeployRegistries.s.sol   --rpc-url http://127.0.0.1:8545 --broadcast --private-key $PK
//	forge script script/SeedBrokerFixture.s.sol  --rpc-url http://127.0.0.1:8545 --broadcast --private-key $PK
//	go test -tags integration ./internal/chainrpc/
//
// These are behind a build tag because they need infrastructure CI does not
// currently provide. They are the only tests that prove the hand-rolled ABI
// encoding actually reaches the intended functions on real bytecode.
package chainrpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/binding"
)

type fixture struct {
	ChainID          int64  `json:"chainId"`
	IdentityRegistry string `json:"identityRegistry"`
	Operator         string `json:"operator"`
	Buyer            string `json:"buyer"`
	LiveAgentID      int64  `json:"liveAgentId"`
	LiveAgentURI     string `json:"liveAgentURI"`
	SoldAgentID      int64  `json:"soldAgentId"`
	AbsentAgentID    int64  `json:"absentAgentId"`
}

func rpcURL() string {
	if v := os.Getenv("SATM_RPC_URL"); v != "" {
		return v
	}
	return "http://127.0.0.1:8545"
}

func loadFixture(t *testing.T) fixture {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "contracts", "deployments", "broker-fixture-31337.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture not found at %s; run the seed script first: %v", path, err)
	}
	var f fixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return f
}

func mustAddr(t *testing.T, s string) [20]byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(s), "0x"))
	if err != nil || len(b) != 20 {
		t.Fatalf("bad address %q", s)
	}
	var out [20]byte
	copy(out[:], b)
	return out
}

func liveClient(t *testing.T) *Client {
	t.Helper()
	c, err := New(DefaultConfig(rpcURL()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// TestLiveOwnerOf proves the ownerOf calldata reaches the real ERC-721.
func TestLiveOwnerOf(t *testing.T) {
	f := loadFixture(t)
	c := liveClient(t)
	registry := mustAddr(t, f.IdentityRegistry)

	owner, err := c.OwnerOf(context.Background(), registry, big.NewInt(f.LiveAgentID))
	if err != nil {
		t.Fatalf("OwnerOf: %v", err)
	}
	want := mustAddr(t, f.Operator)
	if owner != want {
		t.Fatalf("owner = 0x%s, want 0x%s", hex.EncodeToString(owner[:]), hex.EncodeToString(want[:]))
	}
}

// TestLiveGetAgentWallet is the assertion the stub tests cannot make: there is
// no publicly documented selector for getAgentWallet(uint256), so only a real
// call can confirm the derivation is right.
func TestLiveGetAgentWallet(t *testing.T) {
	f := loadFixture(t)
	c := liveClient(t)
	registry := mustAddr(t, f.IdentityRegistry)

	wallet, err := c.GetAgentWallet(context.Background(), registry, big.NewInt(f.LiveAgentID))
	if err != nil {
		t.Fatalf("GetAgentWallet: %v", err)
	}
	want := mustAddr(t, f.Operator)
	if wallet != want {
		t.Fatalf("agentWallet = 0x%s, want 0x%s (selector derivation may be wrong)",
			hex.EncodeToString(wallet[:]), hex.EncodeToString(want[:]))
	}
}

// TestLiveAgentWalletClearedOnTransfer is THE load-bearing property, observed
// through the same code path the broker uses in production.
//
// SPECIFICATION.md 7.3.2 / ADR-0003 / TH-5 all depend on a sold agent's wallet
// reading as zero. The Solidity test asserts this at the contract level; this
// one asserts the broker actually SEES it over JSON-RPC.
func TestLiveAgentWalletClearedOnTransfer(t *testing.T) {
	f := loadFixture(t)
	c := liveClient(t)
	registry := mustAddr(t, f.IdentityRegistry)
	ctx := context.Background()

	owner, err := c.OwnerOf(ctx, registry, big.NewInt(f.SoldAgentID))
	if err != nil {
		t.Fatalf("OwnerOf(sold): %v", err)
	}
	wantBuyer := mustAddr(t, f.Buyer)
	if owner != wantBuyer {
		t.Fatalf("precondition failed: sold agent owner = 0x%s, want the buyer 0x%s",
			hex.EncodeToString(owner[:]), hex.EncodeToString(wantBuyer[:]))
	}

	wallet, err := c.GetAgentWallet(ctx, registry, big.NewInt(f.SoldAgentID))
	if err != nil {
		t.Fatalf("GetAgentWallet(sold): %v", err)
	}
	if wallet != ([20]byte{}) {
		t.Fatalf("agentWallet after transfer = 0x%s, want zero; "+
			"a sold agent's bindings would remain live (TH-5)", hex.EncodeToString(wallet[:]))
	}
}

// TestLiveAgentURI proves the dynamic `string` return decoder works against real
// ABI output rather than a hand-built fixture.
func TestLiveAgentURI(t *testing.T) {
	f := loadFixture(t)
	c := liveClient(t)
	registry := mustAddr(t, f.IdentityRegistry)

	uri, err := c.AgentURI(context.Background(), registry, big.NewInt(f.LiveAgentID))
	if err != nil {
		t.Fatalf("AgentURI: %v", err)
	}
	if uri != f.LiveAgentURI {
		t.Fatalf("agentURI = %q, want %q", uri, f.LiveAgentURI)
	}
}

// TestLiveAbsentAgentIsNotFound pins that a real ERC721NonexistentToken revert
// maps to ErrAgentNotFound, which is what the verifier's B7 check branches on.
func TestLiveAbsentAgentIsNotFound(t *testing.T) {
	f := loadFixture(t)
	c := liveClient(t)
	registry := mustAddr(t, f.IdentityRegistry)

	_, err := c.OwnerOf(context.Background(), registry, big.NewInt(f.AbsentAgentID))
	if !errors.Is(err, binding.ErrAgentNotFound) {
		t.Fatalf("OwnerOf(absent) err = %v, want ErrAgentNotFound", err)
	}
}

// TestLiveEOAIsNotAnERC1271Wallet checks the EIP-1271 path against a real
// externally-owned account: eth_call on an address with no code succeeds and
// returns empty, which must read as a rejection.
func TestLiveEOAIsNotAnERC1271Wallet(t *testing.T) {
	f := loadFixture(t)
	c := liveClient(t)

	ok, err := c.IsValidERC1271Signature(context.Background(),
		mustAddr(t, f.Operator), [32]byte{}, make([]byte, 65))
	if err != nil {
		t.Fatalf("IsValidERC1271Signature: %v", err)
	}
	if ok {
		t.Fatal("an EOA was accepted as a valid ERC-1271 signer")
	}
}

// TestLiveQuorumAcrossSameNode is a sanity check that fan-out and result
// comparison behave against a real node: querying the same endpoint twice must
// agree, not spuriously report disagreement.
func TestLiveQuorumAcrossSameNode(t *testing.T) {
	f := loadFixture(t)
	c, err := New(DefaultConfig(rpcURL(), rpcURL()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	registry := mustAddr(t, f.IdentityRegistry)

	if _, err := c.OwnerOf(context.Background(), registry, big.NewInt(f.LiveAgentID)); err != nil {
		t.Fatalf("2-endpoint quorum against one node failed: %v", err)
	}
}
