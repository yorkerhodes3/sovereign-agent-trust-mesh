// Package config loads and validates satm-broker.yaml.
//
// Validation here is deliberately strict and fails at startup rather than at
// request time. A broker that boots with an empty registry allow-list or a
// nonce retention shorter than its own maxTTL is not "degraded" -- it is
// silently insecure, and the operator has no signal that anything is wrong.
// SPECIFICATION.md 18 is the reference for the file format.
package config

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/binding"
	"github.com/yorkerhodes3/sovereign-agent-trust-mesh/services/broker/internal/fetch"
)

// Config is the broker configuration.
type Config struct {
	Version      string        `yaml:"version"`
	MeshID       string        `yaml:"meshId"`
	ControlPlane ControlPlane  `yaml:"controlPlane"`
	Chains       Chains        `yaml:"chains"`
	Binding      BindingConfig `yaml:"binding"`
	Listen       string        `yaml:"listen"`
}

// ControlPlane addresses the SAM control plane.
type ControlPlane struct {
	URL string `yaml:"url"`
	// RequireManualApproval asserts the mesh runs with
	// --auto-approve-enrollment=false. Spike S-1 confirmed that flag defaults to
	// false upstream; this setting records that SATM depends on it.
	RequireManualApproval bool `yaml:"requireManualApproval"`
}

// Chains groups per-chain settings.
type Chains struct {
	Identity IdentityChain `yaml:"identity"`
}

// IdentityChain is the L2 carrying the ERC-8004 registries.
type IdentityChain struct {
	ChainID          int64    `yaml:"chainId"`
	RPCUrls          []string `yaml:"rpcUrls"`
	RPCQuorum        int      `yaml:"rpcQuorum"`
	Confirmations    int      `yaml:"confirmations"`
	IdentityRegistry string   `yaml:"identityRegistry"`
}

// BindingConfig covers the B1..B15 knobs.
type BindingConfig struct {
	MaxTTL                   time.Duration `yaml:"maxTTL"`
	ClockSkew                time.Duration `yaml:"clockSkew"`
	NonceRetention           time.Duration `yaml:"nonceRetention"`
	TrustedRegistries        []string      `yaml:"trustedRegistries"`
	RequireUniqueAgentWallet bool          `yaml:"requireUniqueAgentWallet"`
	OneActiveBindingPerAgent bool          `yaml:"oneActiveBindingPerAgent"`

	// ReconcileInterval is the upper bound on how long a sold or de-listed agent
	// retains mesh access, so it is a security parameter rather than a tuning
	// knob.
	ReconcileInterval time.Duration `yaml:"reconcileInterval"`

	// ReconcileDryRun reports what would be revoked without revoking it.
	ReconcileDryRun bool `yaml:"reconcileDryRun"`

	Fetch FetchConfig `yaml:"fetch"`
}

// FetchConfig mirrors fetch.Config.
type FetchConfig struct {
	AllowedSchemes     []string      `yaml:"allowedSchemes"`
	MaxBytes           int64         `yaml:"maxBytes"`
	Timeout            time.Duration `yaml:"timeout"`
	MaxRedirects       int           `yaml:"maxRedirects"`
	BlockPrivateRanges *bool         `yaml:"blockPrivateRanges"`
	IPFSGateway        string        `yaml:"ipfsGateway"`
}

// Load reads and validates a config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	return Parse(data)
}

// Parse validates config bytes.
func Parse(data []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true) // a typo'd security setting must be an error, not a silent default
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: parse: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Version == "" {
		c.Version = "v1"
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8081"
	}
	if c.Binding.MaxTTL == 0 {
		c.Binding.MaxTTL = 168 * time.Hour
	}
	if c.Binding.ClockSkew == 0 {
		c.Binding.ClockSkew = 60 * time.Second
	}
	if c.Binding.NonceRetention == 0 {
		c.Binding.NonceRetention = 240 * time.Hour
	}
	if c.Chains.Identity.Confirmations == 0 {
		c.Chains.Identity.Confirmations = 5
	}
	if c.Binding.ReconcileInterval == 0 {
		c.Binding.ReconcileInterval = time.Minute
	}

	d := fetch.DefaultConfig()
	if len(c.Binding.Fetch.AllowedSchemes) == 0 {
		c.Binding.Fetch.AllowedSchemes = d.AllowedSchemes
	}
	if c.Binding.Fetch.MaxBytes == 0 {
		c.Binding.Fetch.MaxBytes = d.MaxBytes
	}
	if c.Binding.Fetch.Timeout == 0 {
		c.Binding.Fetch.Timeout = d.Timeout
	}
	if c.Binding.Fetch.MaxRedirects == 0 {
		c.Binding.Fetch.MaxRedirects = d.MaxRedirects
	}
	if c.Binding.Fetch.IPFSGateway == "" {
		c.Binding.Fetch.IPFSGateway = d.IPFSGateway
	}
	if c.Binding.Fetch.BlockPrivateRanges == nil {
		// A pointer, not a bool, precisely so "absent" defaults to ON rather
		// than to Go's zero value of false.
		on := true
		c.Binding.Fetch.BlockPrivateRanges = &on
	}
}

// Validate rejects configurations that would be insecure or non-functional.
func (c *Config) Validate() error {
	if c.Version != "v1" {
		return fmt.Errorf("config: unsupported version %q (want v1)", c.Version)
	}
	if c.MeshID == "" {
		return fmt.Errorf("config: meshId is required")
	}
	if c.ControlPlane.URL == "" {
		return fmt.Errorf("config: controlPlane.url is required")
	}
	if len(c.Chains.Identity.RPCUrls) == 0 {
		return fmt.Errorf("config: chains.identity.rpcUrls must list at least one endpoint")
	}
	if c.Chains.Identity.ChainID <= 0 {
		return fmt.Errorf("config: chains.identity.chainId is required")
	}
	if q := c.Chains.Identity.RPCQuorum; q < 0 || q > len(c.Chains.Identity.RPCUrls) {
		return fmt.Errorf("config: chains.identity.rpcQuorum %d is not in 0..%d",
			q, len(c.Chains.Identity.RPCUrls))
	}
	if len(c.Binding.TrustedRegistries) == 0 {
		return fmt.Errorf("config: binding.trustedRegistries must not be empty; " +
			"an empty allow-list would accept an attacker-deployed registry (check B2a, TH-3a)")
	}
	if c.Binding.MaxTTL <= 0 {
		return fmt.Errorf("config: binding.maxTTL must be positive")
	}
	// Retention shorter than maxTTL means a still-valid document outlives the
	// record of its own nonce, at which point it can be replayed. This is the
	// single most consequential misconfiguration in the file.
	if c.Binding.NonceRetention <= c.Binding.MaxTTL {
		return fmt.Errorf(
			"config: binding.nonceRetention (%s) must exceed binding.maxTTL (%s); "+
				"otherwise a document outlives its own nonce record and becomes replayable",
			c.Binding.NonceRetention, c.Binding.MaxTTL)
	}
	if _, err := c.TrustedRegistries(); err != nil {
		return err
	}
	if c.Binding.Fetch.MaxBytes <= 0 {
		return fmt.Errorf("config: binding.fetch.maxBytes must be positive")
	}
	if c.Binding.ReconcileInterval <= 0 {
		return fmt.Errorf("config: binding.reconcileInterval must be positive; " +
			"it bounds how long a sold agent retains mesh access (TH-5)")
	}
	return nil
}

// TrustedRegistries parses the allow-list into verifier form.
func (c *Config) TrustedRegistries() ([]binding.TrustedRegistry, error) {
	out := make([]binding.TrustedRegistry, 0, len(c.Binding.TrustedRegistries))
	seen := map[string]bool{}

	for _, raw := range c.Binding.TrustedRegistries {
		tuple := strings.TrimSpace(raw)
		// Lowercase is not cosmetic: SAM label matching is exact and
		// case-sensitive, and the CAID derived from this tuple ends up in
		// attested labels (TH-18).
		if tuple != strings.ToLower(tuple) {
			return nil, fmt.Errorf(
				"config: trusted registry %q must be lowercase; SAM label matching is case-sensitive", raw)
		}
		parts := strings.Split(tuple, ":")
		if len(parts) != 3 {
			return nil, fmt.Errorf("config: trusted registry %q is not namespace:chainId:address", raw)
		}
		ns, chainStr, addrStr := parts[0], parts[1], parts[2]
		if ns != "eip155" {
			return nil, fmt.Errorf("config: trusted registry %q: unsupported namespace %q", raw, ns)
		}
		chainID, ok := new(big.Int).SetString(chainStr, 10)
		if !ok || chainID.Sign() <= 0 {
			return nil, fmt.Errorf("config: trusted registry %q: bad chain id %q", raw, chainStr)
		}
		if !strings.HasPrefix(addrStr, "0x") || len(addrStr) != 42 {
			return nil, fmt.Errorf("config: trusted registry %q: address must be 0x + 40 hex chars", raw)
		}
		addrBytes, err := hex.DecodeString(addrStr[2:])
		if err != nil {
			return nil, fmt.Errorf("config: trusted registry %q: address is not hex: %w", raw, err)
		}
		if seen[tuple] {
			return nil, fmt.Errorf("config: trusted registry %q is listed twice", raw)
		}
		seen[tuple] = true

		var addr [20]byte
		copy(addr[:], addrBytes)
		out = append(out, binding.TrustedRegistry{
			Tuple:     tuple,
			Namespace: ns,
			ChainID:   chainID,
			Address:   addr,
		})
	}
	return out, nil
}

// FetchConfig converts to fetch.Config.
func (c *Config) FetchConfig() fetch.Config {
	d := fetch.DefaultConfig()
	return fetch.Config{
		AllowedSchemes:     c.Binding.Fetch.AllowedSchemes,
		MaxBytes:           c.Binding.Fetch.MaxBytes,
		Timeout:            c.Binding.Fetch.Timeout,
		MaxRedirects:       c.Binding.Fetch.MaxRedirects,
		BlockPrivateRanges: *c.Binding.Fetch.BlockPrivateRanges,
		IPFSGateway:        c.Binding.Fetch.IPFSGateway,
		NegativeCacheTTL:   d.NegativeCacheTTL,
		MaxJSONDepth:       d.MaxJSONDepth,
		MaxJSONArray:       d.MaxJSONArray,
	}
}

// IdentityRegistryAddress returns the configured registry as raw bytes.
func (c *Config) IdentityRegistryAddress() ([20]byte, error) {
	var out [20]byte
	s := strings.TrimPrefix(strings.ToLower(c.Chains.Identity.IdentityRegistry), "0x")
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 20 {
		return out, fmt.Errorf("config: chains.identity.identityRegistry %q is not a 20-byte address",
			c.Chains.Identity.IdentityRegistry)
	}
	copy(out[:], b)
	return out, nil
}

// VerifierConfig assembles the binding.Config.
func (c *Config) VerifierConfig() (binding.Config, error) {
	registries, err := c.TrustedRegistries()
	if err != nil {
		return binding.Config{}, err
	}
	return binding.Config{
		MeshID:                   c.MeshID,
		ControlPlane:             c.ControlPlane.URL,
		MaxTTL:                   c.Binding.MaxTTL,
		ClockSkew:                c.Binding.ClockSkew,
		TrustedRegistries:        registries,
		RequireUniqueAgentWallet: c.Binding.RequireUniqueAgentWallet,
	}, nil
}

// ChainIDString renders the identity chain id for CAIP tuples.
func (c *Config) ChainIDString() string {
	return strconv.FormatInt(c.Chains.Identity.ChainID, 10)
}
