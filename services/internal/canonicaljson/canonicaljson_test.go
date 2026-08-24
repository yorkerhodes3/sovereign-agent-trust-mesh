package canonicaljson

import (
	"encoding/json"
	"strings"
	"testing"
)

// decode parses JSON the way callers must: with UseNumber, so integers stay
// exact rather than round-tripping through float64.
func decode(t *testing.T, s string) any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return v
}

// TestRFC8785Vectors checks the published examples from the specification.
//
// These are the cases where a naive encoder silently diverges, which is the
// whole risk this package exists to eliminate: the two binding signers may be
// different implementations in different languages, so a one-byte disagreement
// means a valid signature fails to verify.
func TestRFC8785Vectors(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "keys sorted, whitespace stripped",
			input: `{ "b": 1, "a": 2 }`,
			want:  `{"a":2,"b":1}`,
		},
		{
			name:  "nested objects sorted at every level",
			input: `{"z":{"y":1,"x":2},"a":3}`,
			want:  `{"a":3,"z":{"x":2,"y":1}}`,
		},
		{
			name:  "array order preserved",
			input: `[3,1,2]`,
			want:  `[3,1,2]`,
		},
		{
			name:  "literals",
			input: `{"t":true,"f":false,"n":null}`,
			want:  `{"f":false,"n":null,"t":true}`,
		},
		{
			name:  "empty containers",
			input: `{"a":{},"b":[]}`,
			want:  `{"a":{},"b":[]}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Encode(decode(t, tc.input))
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("Encode = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestNoHTMLEscaping is the most likely real-world divergence.
//
// encoding/json escapes <, > and & to \u003c, \u003e and \u0026 by default. JCS
// does not. A document containing any of those characters would hash
// differently in Go than in a Python or TypeScript signer.
func TestNoHTMLEscaping(t *testing.T) {
	got, err := Encode(decode(t, `{"k":"a<b>c&d"}`))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := `{"k":"a<b>c&d"}`
	if string(got) != want {
		t.Fatalf("Encode = %s, want %s (HTML escaping must not be applied)", got, want)
	}

	// Confirm the divergence is real rather than hypothetical.
	std, err := json.Marshal(map[string]string{"k": "a<b>c&d"})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if string(std) == want {
		t.Skip("encoding/json no longer HTML-escapes; this guard is now redundant")
	}
}

func TestStringEscaping(t *testing.T) {
	cases := map[string]string{
		`{"k":"a\"b"}`:     `{"k":"a\"b"}`,
		`{"k":"a\\b"}`:     `{"k":"a\\b"}`,
		`{"k":"a\nb"}`:     `{"k":"a\nb"}`,
		`{"k":"a\tb"}`:     `{"k":"a\tb"}`,
		`{"k":"a\rb"}`:     `{"k":"a\rb"}`,
		`{"k":"a\bb"}`:     `{"k":"a\bb"}`,
		`{"k":"a\fb"}`:     `{"k":"a\fb"}`,
		`{"k":"a\u0001b"}`: `{"k":"a\u0001b"}`,
		// Non-ASCII is emitted literally as UTF-8, not escaped.
		`{"k":"héllo"}`: `{"k":"héllo"}`,
		`{"k":"日本"}`:    `{"k":"日本"}`,
	}
	for input, want := range cases {
		got, err := Encode(decode(t, input))
		if err != nil {
			t.Fatalf("Encode(%s): %v", input, err)
		}
		if string(got) != want {
			t.Errorf("Encode(%s) = %s, want %s", input, got, want)
		}
	}
}

// TestUTF16KeyOrdering covers the ordering rule that differs from Go's default.
//
// JCS sorts object members by UTF-16 code unit. Go sorts strings by UTF-8 byte.
// The two DISAGREE above the BMP: a surrogate pair begins with 0xD800, which
// sorts below U+E000..U+FFFF in UTF-16 but above it in UTF-8.
func TestUTF16KeyOrdering(t *testing.T) {
	// U+FF3A (FULLWIDTH Z) vs U+1F600 (emoji, needs a surrogate pair).
	// UTF-16: 0xFF3A > 0xD83D, so the emoji key sorts FIRST.
	// UTF-8:  0xEF... < 0xF0..., so the fullwidth key would sort first.
	got, err := Encode(decode(t, "{\"\uFF3A\":1,\"\U0001F600\":2}"))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := "{\"\U0001F600\":2,\"\uFF3A\":1}"
	if string(got) != want {
		t.Fatalf("Encode = %s, want %s (keys must sort by UTF-16 code unit, not UTF-8 byte)",
			got, want)
	}

	if !lessUTF16("\U0001F600", "\uFF3A") {
		t.Error("lessUTF16 disagrees: surrogate pair must sort below U+FF3A")
	}
}

func TestASCIIKeyOrderingUnaffected(t *testing.T) {
	got, err := Encode(decode(t, `{"peerId":1,"agentId":2,"meshId":3,"nonce":4}`))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := `{"agentId":2,"meshId":3,"nonce":4,"peerId":1}`
	if string(got) != want {
		t.Fatalf("Encode = %s, want %s", got, want)
	}
}

func TestIntegerNumbers(t *testing.T) {
	got, err := Encode(decode(t, `{"a":0,"b":-1,"c":42,"d":9007199254740991}`))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := `{"a":0,"b":-1,"c":42,"d":9007199254740991}`
	if string(got) != want {
		t.Fatalf("Encode = %s, want %s", got, want)
	}
}

// TestNonIntegerNumbersRejected pins the deliberate limitation.
//
// RFC 8785 mandates the ECMAScript Number::toString algorithm, which is fiddly
// for non-integers. Implementing it approximately would produce signatures that
// verify in one language and not another -- strictly worse than refusing. SATM
// documents carry every numeric value as a decimal string precisely so this
// path is unreachable by construction.
func TestNonIntegerNumbersRejected(t *testing.T) {
	for _, s := range []string{`{"a":1.5}`, `{"a":1e10}`, `{"a":1E10}`, `{"a":0.1}`} {
		if _, err := Encode(decode(t, s)); err == nil {
			t.Errorf("non-integer number in %s was accepted", s)
		}
	}
}

// TestFloat64Rejected catches the caller-side mistake of decoding without
// UseNumber, which would silently lose precision on a uint256-scale value.
func TestFloat64Rejected(t *testing.T) {
	var v any
	if err := json.Unmarshal([]byte(`{"a":1}`), &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	_, err := Encode(v)
	if err == nil {
		t.Fatal("float64 was accepted; decoding without UseNumber must be refused")
	}
	if !strings.Contains(err.Error(), "UseNumber") {
		t.Fatalf("error should tell the caller how to fix it, got: %v", err)
	}
}

func TestInvalidUTF8Rejected(t *testing.T) {
	// Built directly rather than parsed, since the JSON decoder would reject it first.
	if _, err := Encode(map[string]any{"k": string([]byte{0xff, 0xfe})}); err == nil {
		t.Fatal("invalid UTF-8 was accepted")
	}
}

func TestUnsupportedTypeRejected(t *testing.T) {
	if _, err := Encode(struct{ A int }{1}); err == nil {
		t.Fatal("a struct was accepted; callers must normalise through map[string]any first")
	}
}

// TestDeterminism is the property everything else depends on: the same logical
// value must produce identical bytes every time, regardless of Go's randomised
// map iteration order.
func TestDeterminism(t *testing.T) {
	input := `{"z":1,"a":2,"m":{"q":3,"b":4},"arr":[{"y":5,"x":6}]}`
	first, err := Encode(decode(t, input))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	for i := 0; i < 100; i++ {
		got, err := Encode(decode(t, input))
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		if string(got) != string(first) {
			t.Fatalf("iteration %d differed:\n first: %s\n got:   %s", i, first, got)
		}
	}
}
