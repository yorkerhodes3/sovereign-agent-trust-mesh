package canonicaljson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Encode serialises v per RFC 8785 (JSON Canonicalization Scheme).
//
// Why this is hand-rolled rather than encoding/json:
//
// Both binding signatures are computed over these bytes, and the two signers may
// not be the same implementation -- an agent operator might sign with a Python or
// TypeScript tool while the broker verifies in Go. If the two disagree about a
// single byte, a valid signature fails to verify, or worse, an attacker finds an
// input where they disagree in a useful direction.
//
// Go's encoding/json is close to JCS but not equal to it:
//
//   - it HTML-escapes <, > and & by default, which JCS does not
//   - it does not guarantee lexicographic ordering by UTF-16 code unit, which
//     JCS requires (Go sorts map keys as Go strings, i.e. by UTF-8 byte order)
//   - it re-formats numbers via strconv in a way that does not match the
//     ECMAScript Number::toString algorithm JCS mandates
//
// The first two matter for our documents today; the third is guarded against by
// rejecting non-integer numbers outright (see below), because binding documents
// carry every numeric value as a string precisely to avoid that problem.
func Encode(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonical(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
		return nil
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return nil
	case string:
		return writeCanonicalString(buf, t)
	case json.Number:
		return writeCanonicalNumber(buf, t)
	case float64:
		// Reachable only if a caller decodes without UseNumber. Binding
		// documents never contain JSON numbers, so treat this as a programming
		// error rather than guessing at a representation.
		return fmt.Errorf("canonical json: float64 encountered (%v); decode with "+
			"json.Decoder.UseNumber so numbers stay exact", t)
	case map[string]any:
		return writeCanonicalObject(buf, t)
	case []any:
		buf.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	default:
		return fmt.Errorf("canonical json: unsupported type %T", v)
	}
}

func writeCanonicalObject(buf *bytes.Buffer, m map[string]any) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// JCS orders members by their UTF-16 code units, NOT by UTF-8 bytes. The two
	// differ for characters above U+FFFF: a surrogate pair starts with 0xD800,
	// which sorts BELOW U+E000..U+FFFF in UTF-16 but ABOVE it in UTF-8. Our own
	// keys are all ASCII, where the orders coincide, but sorting correctly costs
	// nothing and means this function stays right if the schema ever grows a
	// non-ASCII key.
	sort.Slice(keys, func(i, j int) bool {
		return lessUTF16(keys[i], keys[j])
	})

	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := writeCanonicalString(buf, k); err != nil {
			return err
		}
		buf.WriteByte(':')
		if err := writeCanonical(buf, m[k]); err != nil {
			return err
		}
	}
	buf.WriteByte('}')
	return nil
}

// lessUTF16 compares two strings by UTF-16 code unit, as RFC 8785 requires.
func lessUTF16(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// writeCanonicalString emits a JSON string using JCS escaping rules: the two-char
// escapes where they exist, \u00XX for other control characters, and literal
// UTF-8 for everything else. Notably it does NOT escape <, >, & or U+2028/U+2029,
// which encoding/json does by default.
func writeCanonicalString(buf *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("canonical json: string is not valid UTF-8")
	}
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
	return nil
}

// writeCanonicalNumber emits a JSON number.
//
// RFC 8785 requires the ECMAScript Number::toString algorithm, which is
// genuinely fiddly for non-integers (shortest round-trip representation,
// exponent thresholds at 1e21 and 1e-7). Rather than implement it approximately
// and hope, this rejects anything that is not an exact integer.
//
// That is safe here BY CONSTRUCTION: binding documents carry every numeric value
// as a decimal string (agentId, nonce) specifically so that uint256 values
// survive intact and no float ever enters the signing path. If a future schema
// adds a real JSON number, this function must grow a full ECMAScript
// implementation rather than being loosened.
func writeCanonicalNumber(buf *bytes.Buffer, n json.Number) error {
	s := n.String()
	if strings.ContainsAny(s, ".eE") {
		return fmt.Errorf("canonical json: non-integer number %q is not supported; "+
			"carry numeric values as decimal strings", s)
	}
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("canonical json: number %q is not a 64-bit integer: %w", s, err)
	}
	buf.WriteString(strconv.FormatInt(i, 10))
	return nil
}
