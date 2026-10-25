package zerojwt

import (
	"bytes"
	"testing"
	"time"
)

func TestV231_VerifyNowHelpers(t *testing.T) {
	secret := []byte("secret-key-at-least-32-bytes-long!")
	v, err := New(secret)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	tok, err := v.SignClaims(nil, StandardClaims{
		Subject:   "alice",
		ExpiresAt: now + 300,
	})
	if err != nil {
		t.Fatal(err)
	}

	var claims Claims
	if err := v.VerifyNow(tok, &claims); err != nil {
		t.Fatalf("VerifyNow failed: %v", err)
	}
	if string(claims.Subject()) != "alice" {
		t.Fatalf("expected alice, got %s", string(claims.Subject()))
	}

	// VerifyBearerNow
	bearerHdr := append([]byte("Bearer "), tok...)
	if err := v.VerifyBearerNow(bearerHdr, &claims); err != nil {
		t.Fatalf("VerifyBearerNow failed: %v", err)
	}

	// VerifySplitNow
	dot := bytes.IndexByte(tok, '.')
	if err := v.VerifySplitNow(tok[:dot+1], tok[dot+1:], &claims); err != nil {
		t.Fatalf("VerifySplitNow failed: %v", err)
	}
}
