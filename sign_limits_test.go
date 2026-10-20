package zerojwt

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// Regression: Sign/SignWithScratch/SignClaims used to sign payloads larger than MaxPayloadSize,
// producing tokens that the very same Verifier then rejected with ErrPayloadTooLarge.
// A Verifier must never issue a token it cannot verify.
func TestRegression_SignRespectsMaxPayloadSize(t *testing.T) {
	const limit = 64
	v := NewVerifierWithOptions([]byte(secA), Options{MaxPayloadSize: limit})

	// Exactly at the limit: signs and verifies.
	atLimit := []byte(`{"sub":"u","exp":4102444800,"pad":"` +
		strings.Repeat("x", limit-len(`{"sub":"u","exp":4102444800,"pad":""}`)) + `"}`)
	if len(atLimit) != limit {
		t.Fatalf("test setup: payload is %d bytes, want %d", len(atLimit), limit)
	}
	tok := v.Sign(nil, atLimit)
	if tok == nil {
		t.Fatal("payload exactly at MaxPayloadSize must be signed")
	}
	var c Claims
	if err := v.Verify(tok, tnow, &c); err != nil {
		t.Fatalf("token at MaxPayloadSize must verify: %v", err)
	}

	// One byte over: every Sign entry point refuses instead of issuing an unverifiable token.
	over := append(append([]byte(nil), atLimit[:len(atLimit)-2]...), 'x', '"', '}')
	if len(over) != limit+1 {
		t.Fatalf("test setup: payload is %d bytes, want %d", len(over), limit+1)
	}
	if got := v.Sign(nil, over); got != nil {
		t.Errorf("Sign: want nil for oversized payload, got %q", got)
	}
	if got := v.SignWithScratch(nil, over, v.NewScratch()); got != nil {
		t.Errorf("SignWithScratch: want nil for oversized payload, got %q", got)
	}
	dst := []byte("prefix")
	if got := v.SignHS256(dst, over); got != nil {
		t.Errorf("SignHS256: want nil for oversized payload, got %q", got)
	}
	if !bytes.Equal(dst, []byte("prefix")) {
		t.Error("refused Sign must not modify dst")
	}

	long := []byte(strings.Repeat("u", limit))
	if got := v.SignClaims(nil, long, nil, tnow, tnow+60); got != nil {
		t.Errorf("SignClaims: want nil for oversized payload, got %q", got)
	}

	b := v.NewSigner(nil)
	if got, err := b.SetSubject(long).SetExpiresAt(tnow + 60).Sign(); got != nil || !errors.Is(err, ErrPayloadTooLarge) {
		t.Errorf("SignBuilder: want (nil, ErrPayloadTooLarge), got (%q, %v)", got, err)
	}

	// The asymmetry the guard closes: an oversized token signed elsewhere is still rejected on Verify.
	big := NewVerifierWithOptions([]byte(secA), Options{MaxPayloadSize: 4096})
	bigTok := big.Sign(nil, over)
	if bigTok == nil {
		t.Fatal("verifier with a larger limit must sign the payload")
	}
	if err := v.Verify(bigTok, tnow, &c); !errors.Is(err, ErrPayloadTooLarge) {
		t.Errorf("Verify: want ErrPayloadTooLarge, got %v", err)
	}
}
