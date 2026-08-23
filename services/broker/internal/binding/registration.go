package binding

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// RegistrationFileType is the ERC-8004 registration file schema identifier.
const RegistrationFileType = "https://eips.ethereum.org/EIPS/eip-8004#registration-v1"

// RegistrationFile is the subset of an ERC-8004 registration file the binding
// verifier reads (checks B11-B13).
//
// Only the fields SATM actually uses are modelled. Unknown fields are IGNORED
// here -- unlike the binding document, which rejects them -- because the
// registration file is a third-party document governed by ERC-8004, which
// explicitly allows arbitrary additional service entries. Rejecting unknown
// fields would make SATM break on a conformant file.
type RegistrationFile struct {
	Type           string         `json:"type"`
	Name           string         `json:"name"`
	Description    string         `json:"description"`
	Image          string         `json:"image"`
	Services       []Service      `json:"services"`
	Active         bool           `json:"active"`
	Registrations  []Registration `json:"registrations"`
	SupportedTrust []string       `json:"supportedTrust"`

	// DomainVerified is NOT part of ERC-8004. It is set by the fetcher when the
	// optional .well-known endpoint-domain check (B14) succeeded, and is carried
	// here so the verifier can surface it as a trust signal without performing
	// the fetch itself.
	DomainVerified bool `json:"-"`
}

// Service is one advertised endpoint.
type Service struct {
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
	Version  string `json:"version,omitempty"`
}

// Registration binds the file back to an on-chain identity.
//
// AgentID is json.Number because ERC-8004 writes it as a JSON *number* while
// SATM carries it as a decimal string everywhere else. Decoding into a string
// would fail; decoding into a float64 would lose precision above 2^53.
type Registration struct {
	AgentID       json.Number `json:"agentId"`
	AgentRegistry string      `json:"agentRegistry"`
}

// ParseRegistrationFile decodes a registration file with bounded structural
// validation.
func ParseRegistrationFile(data []byte) (*RegistrationFile, error) {
	var f RegistrationFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("decode registration file: %w", err)
	}
	if f.Type != RegistrationFileType {
		return nil, fmt.Errorf("registration file type is %q, expected %q", f.Type, RegistrationFileType)
	}
	return &f, nil
}

// HasRegistration implements the B11 comparison.
//
// The registry tuple comparison is case-insensitive on the ADDRESS portion only,
// because ERC-8004 does not mandate lowercase and real files in the wild carry
// EIP-55 checksummed addresses. SATM's own documents are strictly lowercase
// (see Document.Validate), so this leniency applies solely to third-party data
// we did not author and cannot dictate.
func (f *RegistrationFile) HasRegistration(registryTuple, agentID string) bool {
	for _, r := range f.Registrations {
		if r.AgentID.String() != agentID {
			continue
		}
		if strings.EqualFold(r.AgentRegistry, registryTuple) {
			return true
		}
	}
	return false
}

// samURIPattern matches the SATM-defined sam:// URI grammar:
//
//	sam://<peer-id>@<mesh-id>[/<service-type>/<service-name>]
//
// service-type and service-name deliberately mirror SAM's own "type://name"
// service format, so a resolved URI maps directly onto call_remote_tool
// arguments without a translation step.
var samURIPattern = regexp.MustCompile(
	`^sam://([1-9A-HJ-NP-Za-km-z]{44,64})@([A-Za-z0-9._-]{1,63})(?:/(mcp|inference|a2a)/([A-Za-z0-9._-]{1,63}))?$`)

// ParseSAMURI extracts the peer id and mesh id from a sam:// URI.
func ParseSAMURI(uri string) (peerID, meshID string, err error) {
	m := samURIPattern.FindStringSubmatch(uri)
	if m == nil {
		return "", "", fmt.Errorf("%q is not a valid sam:// URI", uri)
	}
	return m[1], m[2], nil
}

// AdvertisesSAM implements the B12 comparison: does this file advertise EXACTLY
// this peer on EXACTLY this mesh?
//
// Both must match. A file advertising the right PeerID on a different mesh is
// not evidence for a binding on this one -- that is the cross-mesh replay the
// meshId field exists to prevent.
func (f *RegistrationFile) AdvertisesSAM(peerID, meshID string) bool {
	for _, s := range f.Services {
		if !strings.EqualFold(s.Name, "SAM") {
			continue
		}
		p, m, err := ParseSAMURI(s.Endpoint)
		if err != nil {
			continue
		}
		if p == peerID && m == meshID {
			return true
		}
	}
	return false
}

// FormatSAMURI builds a sam:// URI. Used by satm-cli when publishing a
// registration file, so the writer and the reader share one grammar.
func FormatSAMURI(peerID, meshID string) string {
	return fmt.Sprintf("sam://%s@%s", peerID, meshID)
}
