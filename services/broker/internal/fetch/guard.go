package fetch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
)

// blockedNets are the CIDR ranges the fetcher refuses to connect to.
//
// The registration file URI is chosen by an untrusted party, so without this an
// agentURI of https://internal-admin.corp/ or http://169.254.169.254/ turns the
// broker into a confused deputy with network access the attacker does not have.
// 169.254.169.254 in particular is the cloud instance-metadata endpoint on AWS,
// GCP and Azure -- the single highest-value SSRF target there is.
var blockedNets = []struct {
	cidr   string
	reason string
	net    *net.IPNet
}{
	{cidr: "0.0.0.0/8", reason: "this-network"},
	{cidr: "10.0.0.0/8", reason: "private (RFC 1918)"},
	{cidr: "100.64.0.0/10", reason: "CGNAT (RFC 6598)"},
	{cidr: "127.0.0.0/8", reason: "loopback"},
	{cidr: "169.254.0.0/16", reason: "link-local / cloud instance metadata"},
	{cidr: "172.16.0.0/12", reason: "private (RFC 1918)"},
	{cidr: "192.0.0.0/24", reason: "IETF protocol assignments"},
	{cidr: "192.0.2.0/24", reason: "TEST-NET-1"},
	{cidr: "192.168.0.0/16", reason: "private (RFC 1918)"},
	{cidr: "198.18.0.0/15", reason: "benchmarking"},
	{cidr: "198.51.100.0/24", reason: "TEST-NET-2"},
	{cidr: "203.0.113.0/24", reason: "TEST-NET-3"},
	{cidr: "224.0.0.0/4", reason: "multicast"},
	{cidr: "240.0.0.0/4", reason: "reserved"},
	{cidr: "255.255.255.255/32", reason: "broadcast"},
	{cidr: "::1/128", reason: "IPv6 loopback"},
	{cidr: "::/128", reason: "IPv6 unspecified"},
	{cidr: "fc00::/7", reason: "IPv6 unique local"},
	{cidr: "fe80::/10", reason: "IPv6 link-local"},
	{cidr: "ff00::/8", reason: "IPv6 multicast"},
	// IPv4-mapped IPv6 (::ffff:127.0.0.1) is handled by the To4() normalisation
	// in BlockedIP rather than by a CIDR, because the mapped form must be
	// checked against the IPv4 ranges above.
	{cidr: "64:ff9b::/96", reason: "IPv4/IPv6 translation"},
	{cidr: "2002::/16", reason: "6to4"},
}

func init() {
	for i := range blockedNets {
		_, n, err := net.ParseCIDR(blockedNets[i].cidr)
		if err != nil {
			panic(fmt.Sprintf("fetch: bad blocked CIDR %q: %v", blockedNets[i].cidr, err))
		}
		blockedNets[i].net = n
	}
}

// BlockedIP returns a human-readable reason if ip must not be connected to, or
// "" if the address is acceptable.
//
// Exported so tests can assert on the policy directly rather than inferring it
// from dial failures.
func BlockedIP(ip net.IP) string {
	if ip == nil {
		return "not an IP address"
	}
	// Normalise IPv4-mapped IPv6 (::ffff:127.0.0.1) down to its IPv4 form first.
	// Skipping this is a classic bypass: the mapped address is not inside
	// 127.0.0.0/8 as a 16-byte value, but it routes to loopback all the same.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, b := range blockedNets {
		if b.net.Contains(ip) {
			return b.reason
		}
	}
	// Defence in depth: catch anything the CIDR list missed.
	switch {
	case ip.IsLoopback():
		return "loopback"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return "link-local"
	case ip.IsPrivate():
		return "private"
	case ip.IsUnspecified():
		return "unspecified"
	}
	return ""
}

// CheckJSONShape rejects structurally abusive JSON before it is unmarshalled
// into Go values (threat TH-9).
//
// Size alone is not enough. A 40 KB document of nothing but "[[[[[..." is well
// under any byte cap yet can exhaust the stack or balloon allocations during
// decoding. Streaming over the token sequence bounds nesting depth and array
// length WITHOUT materialising the document first, which is the whole point --
// checking after unmarshalling would mean the damage is already done.
func CheckJSONShape(data []byte, maxDepth, maxArrayLen int) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	// frame tracks one open container. Keeping object frames on the stack too
	// (rather than only arrays) is what makes the element count correct: a
	// scalar nested inside an object inside an array must NOT be charged to the
	// enclosing array.
	type frame struct {
		isArray bool
		count   int
	}
	var stack []frame
	sawToken := false

	// charge attributes one value to the innermost container, if that container
	// is an array.
	charge := func() error {
		n := len(stack)
		if n == 0 || !stack[n-1].isArray {
			return nil
		}
		stack[n-1].count++
		if stack[n-1].count > maxArrayLen {
			return fmt.Errorf("JSON array exceeds %d elements", maxArrayLen)
		}
		return nil
	}

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("malformed JSON: %w", err)
		}
		sawToken = true

		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{', '[':
				// A nested container is itself an element of any enclosing array.
				if err := charge(); err != nil {
					return err
				}
				stack = append(stack, frame{isArray: delim == '['})
				if len(stack) > maxDepth {
					return fmt.Errorf("JSON nesting exceeds %d levels", maxDepth)
				}
			case '}', ']':
				if len(stack) == 0 {
					return fmt.Errorf("unbalanced JSON structure")
				}
				stack = stack[:len(stack)-1]
			}
			continue
		}

		// Inside an object, Token() yields key and value alternately. Object
		// members are not counted at all, so no key/value bookkeeping is needed;
		// only array elements are charged.
		if err := charge(); err != nil {
			return err
		}
	}

	if len(stack) != 0 {
		return fmt.Errorf("unbalanced JSON structure")
	}
	// An empty body yields EOF on the first Token() call with a balanced (empty)
	// stack, so it would otherwise slip through as "valid".
	if !sawToken {
		return fmt.Errorf("empty JSON document")
	}
	return nil
}
