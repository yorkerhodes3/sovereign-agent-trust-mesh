package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/config"
)

const minimalYAML = `
version: v1
meshId: satm-dev
controlPlane:
  url: http://127.0.0.1:8080
  requireManualApproval: true
chains:
  identity:
    chainId: 31337
    rpcUrls: ["http://127.0.0.1:8545"]
    identityRegistry: "0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0"
binding:
  maxTTL: 168h
  clockSkew: 60s
  nonceRetention: 240h
  trustedRegistries:
    - "eip155:31337:0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0"
  requireUniqueAgentWallet: true
  oneActiveBindingPerAgent: true
`

func TestParseMinimal(t *testing.T) {
	c, err := config.Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.MeshID != "satm-dev" {
		t.Errorf("meshId = %q", c.MeshID)
	}
	if c.Binding.MaxTTL != 168*time.Hour {
		t.Errorf("maxTTL = %v", c.Binding.MaxTTL)
	}
	if c.Listen != "127.0.0.1:8081" {
		t.Errorf("listen default = %q", c.Listen)
	}
}

// TestBlockPrivateRangesDefaultsOn is why that field is a *bool: with a plain
// bool, omitting it would yield Go's zero value and silently DISABLE the SSRF
// guard. A security default must not depend on the language's zero value.
func TestBlockPrivateRangesDefaultsOn(t *testing.T) {
	c, err := config.Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !c.FetchConfig().BlockPrivateRanges {
		t.Fatal("blockPrivateRanges defaulted to false; SSRF protection would be off by default")
	}
}

func TestBlockPrivateRangesCanBeDisabledExplicitly(t *testing.T) {
	y := minimalYAML + `
  fetch:
    blockPrivateRanges: false
`
	c, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if c.FetchConfig().BlockPrivateRanges {
		t.Fatal("explicit false was not honoured")
	}
}

// TestNonceRetentionMustExceedMaxTTL is the highest-consequence validation in
// the file: shorter retention makes still-valid documents replayable.
func TestNonceRetentionMustExceedMaxTTL(t *testing.T) {
	y := strings.Replace(minimalYAML, "nonceRetention: 240h", "nonceRetention: 24h", 1)
	_, err := config.Parse([]byte(y))
	if err == nil {
		t.Fatal("nonceRetention shorter than maxTTL was accepted")
	}
	if !strings.Contains(err.Error(), "replayable") {
		t.Fatalf("error does not explain the consequence: %v", err)
	}

	// Equal is also unsafe -- there is no margin at all.
	y = strings.Replace(minimalYAML, "nonceRetention: 240h", "nonceRetention: 168h", 1)
	if _, err := config.Parse([]byte(y)); err == nil {
		t.Fatal("nonceRetention equal to maxTTL was accepted")
	}
}

func TestEmptyTrustedRegistriesRejected(t *testing.T) {
	y := strings.Replace(minimalYAML,
		"  trustedRegistries:\n    - \"eip155:31337:0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0\"\n",
		"  trustedRegistries: []\n", 1)
	_, err := config.Parse([]byte(y))
	if err == nil {
		t.Fatal("empty trustedRegistries was accepted; this is TH-3a")
	}
	if !strings.Contains(err.Error(), "B2a") {
		t.Fatalf("error should cite check B2a: %v", err)
	}
}

// TestUppercaseRegistryRejected guards TH-18: the tuple flows into SAM labels,
// which are matched exactly and case-sensitively.
func TestUppercaseRegistryRejected(t *testing.T) {
	y := strings.Replace(minimalYAML,
		"eip155:31337:0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0",
		"eip155:31337:0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0", 1)
	_, err := config.Parse([]byte(y))
	if err == nil {
		t.Fatal("checksummed (mixed-case) registry tuple was accepted")
	}
	if !strings.Contains(err.Error(), "lowercase") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMalformedRegistryTuplesRejected(t *testing.T) {
	bad := map[string]string{
		"missing chain":     "eip155:0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0",
		"wrong namespace":   "solana:31337:0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0",
		"short address":     "eip155:31337:0x9fe467",
		"non-hex address":   "eip155:31337:0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
		"zero chain id":     "eip155:0:0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0",
		"non-numeric chain": "eip155:mainnet:0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0",
	}
	for name, tuple := range bad {
		y := strings.Replace(minimalYAML,
			"eip155:31337:0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0", tuple, 1)
		if _, err := config.Parse([]byte(y)); err == nil {
			t.Errorf("%s: tuple %q was accepted", name, tuple)
		}
	}
}

func TestDuplicateRegistryRejected(t *testing.T) {
	y := minimalYAML + `    - "eip155:31337:0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0"
`
	if _, err := config.Parse([]byte(y)); err == nil {
		t.Fatal("duplicate registry tuple was accepted")
	}
}

// TestUnknownFieldsRejected matters because a misspelled security setting that
// parses to a default is worse than one that fails loudly.
func TestUnknownFieldsRejected(t *testing.T) {
	y := minimalYAML + `
  requireUniqueAgentWallets: true
`
	if _, err := config.Parse([]byte(y)); err == nil {
		t.Fatal("unknown field was silently ignored")
	}
}

func TestRequiredFieldsEnforced(t *testing.T) {
	cases := map[string]string{
		"meshId":       "meshId: satm-dev",
		"controlPlane": "  url: http://127.0.0.1:8080",
	}
	for name, line := range cases {
		y := strings.Replace(minimalYAML, line, "", 1)
		if _, err := config.Parse([]byte(y)); err == nil {
			t.Errorf("%s: missing field was accepted", name)
		}
	}

	noRPC := strings.Replace(minimalYAML, `    rpcUrls: ["http://127.0.0.1:8545"]`, "", 1)
	if _, err := config.Parse([]byte(noRPC)); err == nil {
		t.Error("missing rpcUrls was accepted")
	}

	noChain := strings.Replace(minimalYAML, "    chainId: 31337", "", 1)
	if _, err := config.Parse([]byte(noChain)); err == nil {
		t.Error("missing chainId was accepted")
	}
}

func TestQuorumBounds(t *testing.T) {
	y := minimalYAML + `
`
	y = strings.Replace(y, `    rpcUrls: ["http://127.0.0.1:8545"]`,
		"    rpcUrls: [\"http://a\", \"http://b\"]\n    rpcQuorum: 5", 1)
	if _, err := config.Parse([]byte(y)); err == nil {
		t.Fatal("quorum larger than the endpoint count was accepted")
	}
}

func TestVerifierConfigRoundTrip(t *testing.T) {
	c, err := config.Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	vc, err := c.VerifierConfig()
	if err != nil {
		t.Fatalf("VerifierConfig: %v", err)
	}
	if vc.MeshID != "satm-dev" {
		t.Errorf("meshId = %q", vc.MeshID)
	}
	if len(vc.TrustedRegistries) != 1 {
		t.Fatalf("registries = %d, want 1", len(vc.TrustedRegistries))
	}
	reg := vc.TrustedRegistries[0]
	if reg.ChainID.Int64() != 31337 {
		t.Errorf("chainId = %s", reg.ChainID)
	}
	if reg.Namespace != "eip155" {
		t.Errorf("namespace = %q", reg.Namespace)
	}
	if !vc.RequireUniqueAgentWallet {
		t.Error("requireUniqueAgentWallet was not carried through")
	}
}

func TestIdentityRegistryAddress(t *testing.T) {
	c, err := config.Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	addr, err := c.IdentityRegistryAddress()
	if err != nil {
		t.Fatalf("IdentityRegistryAddress: %v", err)
	}
	if addr[0] != 0x9f || addr[19] != 0xe0 {
		t.Fatalf("address = %x", addr)
	}
}

func TestLoadFromDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "satm-broker.yaml")
	if err := os.WriteFile(path, []byte(minimalYAML), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := config.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := config.Load(filepath.Join(dir, "absent.yaml")); err == nil {
		t.Fatal("loading a missing file succeeded")
	}
}

func TestUnsupportedVersionRejected(t *testing.T) {
	y := strings.Replace(minimalYAML, "version: v1", "version: v2", 1)
	if _, err := config.Parse([]byte(y)); err == nil {
		t.Fatal("unsupported version was accepted")
	}
}

// TestRepoConfigIsValid keeps the shipped example honest: a sample config that
// does not actually parse is worse than none.
func TestRepoConfigIsValid(t *testing.T) {
	path := filepath.Join("..", "..", "satm-broker.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no example config at %s", path)
	}
	if _, err := config.Load(path); err != nil {
		t.Fatalf("the example config in the repo does not validate: %v", err)
	}
}
