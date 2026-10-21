package zerojwt_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"
	"unsafe"

	zerojwt "github.com/KaikeGM/zerojwt/v2"
)

func TestClaimsSizeAndAlignment(t *testing.T) {
	var c zerojwt.Claims
	sz := unsafe.Sizeof(c)
	if sz != 1016 {
		t.Fatalf("Claims size must be exactly 1016 bytes, got %d", sz)
	}
	align := unsafe.Alignof(c)
	if align != 8 {
		t.Fatalf("Claims alignment must be 8 bytes, got %d", align)
	}
}

func TestSecureDefaults(t *testing.T) {
	shortSecret := []byte("too-short-secret-less-32-bytes")
	v, err := zerojwt.New(shortSecret)
	if err == nil || v != nil {
		t.Fatalf("expected New with short secret to fail by default, got v=%v, err=%v", v, err)
	}
	if !errors.Is(err, zerojwt.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig, got %v", err)
	}
	if !errors.Is(err, zerojwt.ErrInsecureSecret) {
		t.Fatalf("expected ErrInsecureSecret alias, got %v", err)
	}

	validSecret := bytes.Repeat([]byte("s"), 32)
	v, err = zerojwt.New(validSecret)
	if err != nil || v == nil {
		t.Fatalf("expected New with 32B secret to succeed, got %v", err)
	}

	// Token without exp must be rejected by default
	now := time.Now().Unix()
	var dst []byte
	tokNoExp, err := v.Sign(dst, []byte(`{"sub":"alice"}`))
	if err != nil {
		t.Fatalf("Sign raw JSON failed: %v", err)
	}
	var claims zerojwt.Claims
	err = v.Verify(tokNoExp, now, &claims)
	if !errors.Is(err, zerojwt.ErrMissingExp) {
		t.Fatalf("expected ErrMissingExp for token without exp, got %v", err)
	}

	// Opt-out of strict secret length
	vShort, err := zerojwt.New(shortSecret, zerojwt.Options{AllowShortSecret: true})
	if err != nil || vShort == nil {
		t.Fatalf("expected AllowShortSecret: true to allow short secret, got %v", err)
	}

	// Opt-out of required exp
	vNoExp, err := zerojwt.New(validSecret, zerojwt.Options{AllowMissingExp: true})
	if err != nil || vNoExp == nil {
		t.Fatalf("expected AllowMissingExp: true to succeed, got %v", err)
	}
	err = vNoExp.Verify(tokNoExp, now, &claims)
	if err != nil {
		t.Fatalf("expected token without exp to verify under AllowMissingExp: true, got %v", err)
	}
	if string(claims.Subject()) != "alice" {
		t.Fatalf("expected subject 'alice', got %q", string(claims.Subject()))
	}
}

func TestKeypairCrossValidation(t *testing.T) {
	// 1. Ed25519
	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Mismatched Ed25519 pair
	vEdBad, err := zerojwt.NewEd25519Verifier(pub2, priv1)
	if !errors.Is(err, zerojwt.ErrMismatchedKeyPair) || vEdBad != nil {
		t.Fatalf("expected ErrMismatchedKeyPair for mismatched Ed25519 pair, got v=%v, err=%v", vEdBad, err)
	}

	// Matched Ed25519 pair
	vEdGood, err := zerojwt.NewEd25519Verifier(pub1, priv1)
	if err != nil || vEdGood == nil {
		t.Fatalf("expected valid Ed25519 pair to succeed, got %v", err)
	}

	// 2. ES256
	ecPriv1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecPriv2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Mismatched ES256 pair
	vEcBad, err := zerojwt.NewES256Verifier(&ecPriv2.PublicKey, ecPriv1)
	if !errors.Is(err, zerojwt.ErrMismatchedKeyPair) || vEcBad != nil {
		t.Fatalf("expected ErrMismatchedKeyPair for mismatched ES256 pair, got v=%v, err=%v", vEcBad, err)
	}

	// Matched ES256 pair
	vEcGood, err := zerojwt.NewES256Verifier(&ecPriv1.PublicKey, ecPriv1)
	if err != nil || vEcGood == nil {
		t.Fatalf("expected valid ES256 pair to succeed, got %v", err)
	}
}

func TestBufferRollbackOnSignFailure(t *testing.T) {
	secret := bytes.Repeat([]byte("k"), 32)
	v, err := zerojwt.New(secret)
	if err != nil {
		t.Fatal(err)
	}

	buf := []byte("PREFIX:")
	origLen := len(buf)
	origCap := cap(buf)

	// SignClaims with exp <= 0 should fail with ErrMissingExp and NOT alter buf length
	res, err := v.SignClaims(buf, zerojwt.StandardClaims{
		Subject:   "alice",
		ExpiresAt: 0,
	})
	if !errors.Is(err, zerojwt.ErrMissingExp) {
		t.Fatalf("expected ErrMissingExp, got %v", err)
	}
	if len(res) != origLen {
		t.Fatalf("expected buffer length rolled back to %d, got %d", origLen, len(res))
	}
	if cap(res) != origCap {
		t.Fatalf("expected capacity preserved, got %d vs %d", cap(res), origCap)
	}
	if string(res) != "PREFIX:" {
		t.Fatalf("expected buffer content untouched, got %q", string(res))
	}

	// SignBuilder rollback
	builder := v.NewSigner(buf)
	builder.SetSubject("alice")
	// omitting exp
	resB, err := builder.Sign()
	if !errors.Is(err, zerojwt.ErrMissingExp) {
		t.Fatalf("expected SignBuilder to fail with ErrMissingExp, got %v", err)
	}
	if len(resB) != origLen {
		t.Fatalf("expected SignBuilder buffer length rolled back to %d, got %d", origLen, len(resB))
	}
}
