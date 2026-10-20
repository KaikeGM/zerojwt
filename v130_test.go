package zerojwt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestSecureVerifier(t *testing.T) {
	// 1. SecureOptions values
	opts := SecureOptions()
	if !opts.RequireExp || !opts.StrictSecretLength || opts.Algorithm != AlgHS256 {
		t.Fatalf("unexpected SecureOptions: %+v", opts)
	}

	// 2. Short secret (< 32 bytes) must fail
	shortSec := []byte("too-short-secret")
	if v, err := NewSecureVerifier(shortSec); err == nil || v != nil {
		t.Fatalf("expected error for short secret, got v=%v, err=%v", v, err)
	}

	// 3. Valid secret (>= 32 bytes)
	sec32 := []byte("twelve-dollar-challenge-32-bytes!!")
	v, err := NewSecureVerifier(sec32)
	if err != nil || v == nil {
		t.Fatalf("failed to create secure verifier: %v", err)
	}

	now := time.Now().Unix()

	// 4. Token without exp must be rejected
	noExpTok := v.Sign(nil, []byte(`{"sub":"alice"}`))
	var c Claims
	if err := v.Verify(noExpTok, now, &c); !errors.Is(err, ErrMissingExp) {
		t.Fatalf("expected ErrMissingExp, got %v", err)
	}

	// 5. Token with exp must succeed
	expTok := v.SignClaims(nil, []byte("alice"), nil, now, now+3600)
	if err := v.Verify(expTok, now, &c); err != nil {
		t.Fatalf("expected valid verification, got %v", err)
	}

	// 6. NewSecureVerifierWithOptions with custom options
	customOpts := Options{
		ExpectedIssuer: "auth.company.internal",
	}
	if _, err := NewSecureVerifierWithOptions(shortSec, customOpts); err == nil {
		t.Fatal("expected error with short secret in NewSecureVerifierWithOptions")
	}
	vCustom, err := NewSecureVerifierWithOptions(sec32, customOpts)
	if err != nil || vCustom == nil {
		t.Fatalf("NewSecureVerifierWithOptions failed: %v", err)
	}
	if !vCustom.requireExp {
		t.Fatal("expected requireExp to be enforced")
	}
}

func TestTrySign_AllConditions(t *testing.T) {
	sec32 := []byte("twelve-dollar-challenge-32-bytes!!")
	v := NewVerifier(sec32)
	now := time.Now().Unix()

	// 1. Success with preallocated dst
	var dstBuf [512]byte
	prefix := []byte("token:")
	dst := append(dstBuf[:0], prefix...)
	payload := []byte(`{"sub":"123","exp":` + string(base64.RawURLEncoding.EncodeToString([]byte("x"))) + `}`)
	tok, err := v.TrySign(dst, payload)
	if err != nil {
		t.Fatalf("TrySign failed: %v", err)
	}
	if !bytes.HasPrefix(tok, prefix) {
		t.Fatalf("expected token to retain prefix, got %s", tok)
	}

	// 2. Success with dst == nil
	tokNilDst, err := v.TrySign(nil, payload)
	if err != nil || len(tokNilDst) == 0 {
		t.Fatalf("TrySign with nil dst failed: %v", err)
	}

	// 3. Payload exceeds MaxPayloadSize
	tinyV := NewVerifierWithOptions(sec32, Options{MaxPayloadSize: 32})
	bigPayload := bytes.Repeat([]byte("a"), 40)
	dstUnchanged := []byte("keep-me")
	res, err := tinyV.TrySign(dstUnchanged, bigPayload)
	if !errors.Is(err, ErrPayloadTooLarge) || res != nil {
		t.Fatalf("expected ErrPayloadTooLarge, got res=%v, err=%v", res, err)
	}
	if string(dstUnchanged) != "keep-me" {
		t.Fatalf("expected dst to remain untouched, got %q", dstUnchanged)
	}

	// 4. Verify-only node (no private key)
	pub, _, _ := ed25519.GenerateKey(nil)
	vPubOnly := NewEd25519Verifier(pub, nil, Options{})
	if _, err := vPubOnly.TrySign(nil, payload); !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("expected ErrNoSigningKey, got %v", err)
	}
	if _, err := vPubOnly.TrySignClaims(nil, []byte("u"), nil, now, now+60); !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("expected ErrNoSigningKey for TrySignClaims, got %v", err)
	}

	// 5. Destroyed verifier
	vDestroyed := NewVerifier(sec32)
	vDestroyed.Destroy()
	if _, err := vDestroyed.TrySign(nil, payload); !errors.Is(err, ErrVerifierDestroyed) {
		t.Fatalf("expected ErrVerifierDestroyed, got %v", err)
	}
	if _, err := vDestroyed.TrySignWithScratch(nil, payload, v.NewScratch()); !errors.Is(err, ErrVerifierDestroyed) {
		t.Fatalf("expected ErrVerifierDestroyed for TrySignWithScratch, got %v", err)
	}
	if _, err := vDestroyed.TrySignClaims(nil, []byte("u"), nil, now, now+60); !errors.Is(err, ErrVerifierDestroyed) {
		t.Fatalf("expected ErrVerifierDestroyed for TrySignClaims, got %v", err)
	}
	if _, err := vDestroyed.TrySignClaimsWithScratch(nil, []byte("u"), nil, now, now+60, v.NewScratch()); !errors.Is(err, ErrVerifierDestroyed) {
		t.Fatalf("expected ErrVerifierDestroyed for TrySignClaimsWithScratch, got %v", err)
	}

	// 6. SignBuilder returning typed errors from TrySignWithScratch
	sbDestroyed := vDestroyed.NewSigner(nil)
	if _, err := sbDestroyed.SetSubject([]byte("u")).Sign(); !errors.Is(err, ErrVerifierDestroyed) {
		t.Fatalf("expected SignBuilder to return ErrVerifierDestroyed, got %v", err)
	}
}

func TestTrySignClaims_Limits(t *testing.T) {
	sec32 := []byte("twelve-dollar-challenge-32-bytes!!")
	vReqExp := NewVerifierWithOptions(sec32, Options{RequireExp: true})
	now := time.Now().Unix()

	// 1. RequireExp with exp <= 0
	if _, err := vReqExp.TrySignClaims(nil, []byte("user"), nil, now, 0); !errors.Is(err, ErrMissingExp) {
		t.Fatalf("expected ErrMissingExp for exp=0, got %v", err)
	}

	// 2. Empty sub
	if _, err := vReqExp.TrySignClaims(nil, []byte(""), nil, now, now+60); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for empty sub, got %v", err)
	}

	// 3. sub > 256 bytes
	longSub := bytes.Repeat([]byte("s"), 257)
	if _, err := vReqExp.TrySignClaims(nil, longSub, nil, now, now+60); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for sub > 256, got %v", err)
	}

	// 4. username > 256 bytes
	longUser := bytes.Repeat([]byte("u"), 257)
	if _, err := vReqExp.TrySignClaims(nil, []byte("sub"), longUser, now, now+60); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for username > 256, got %v", err)
	}

	// 5. Valid 200-byte sub verifies with VerifyLarge
	sub200 := bytes.Repeat([]byte("s"), 200)
	tokLarge, err := vReqExp.TrySignClaims(nil, sub200, []byte("admin"), now, now+3600)
	if err != nil {
		t.Fatalf("TrySignClaims failed for 200B sub: %v", err)
	}
	var clLarge ClaimsLarge
	if err := vReqExp.VerifyLarge(tokLarge, now, &clLarge); err != nil {
		t.Fatalf("VerifyLarge failed: %v", err)
	}
	if !bytes.Equal(clLarge.Subject(), sub200) {
		t.Fatal("subject mismatch in VerifyLarge")
	}

	// 5b. A 100-byte sub signed by TrySignClaims succeeds for ClaimsLarge (<= 256B),
	// but is rejected by standard Claims (max 64B subBuf) with ErrInvalidPayload.
	sub100 := bytes.Repeat([]byte("s"), 100)
	tok100, err := vReqExp.TrySignClaims(nil, sub100, []byte("admin"), now, now+3600)
	if err != nil {
		t.Fatalf("TrySignClaims failed for 100B sub: %v", err)
	}
	var stdClaims Claims
	if err := vReqExp.Verify(tok100, now, &stdClaims); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload when verifying 100B sub into standard Claims (max 64B), got %v", err)
	}
	if err := vReqExp.VerifyLarge(tok100, now, &clLarge); err != nil {
		t.Fatalf("expected VerifyLarge to accept 100B sub, got %v", err)
	}

	// 6. Zero allocations check on TrySignClaims
	if !raceDetectorEnabled {
		sub := []byte("user")
		user := []byte("alice")
		var buf [512]byte
		allocs := testing.AllocsPerRun(100, func() {
			_, _ = vReqExp.TrySignClaims(buf[:0], sub, user, now, now+3600)
		})
		if allocs > 0 {
			t.Fatalf("TrySignClaims must perform 0 allocs/op, got %v", allocs)
		}
	}
}

func TestHeaderStrictSeparators(t *testing.T) {
	sec32 := []byte("twelve-dollar-challenge-32-bytes!!")
	v := NewVerifier(sec32)
	now := time.Now().Unix()

	makeTokenWithRawHeader := func(rawHeader string) []byte {
		hdrEnc := base64.RawURLEncoding.EncodeToString([]byte(rawHeader))
		tok := v.Sign(nil, []byte(`{"sub":"123","exp":`+string(base64.RawURLEncoding.EncodeToString([]byte("x")))+`}`))
		// replace header part
		parts := bytes.Split(tok, []byte("."))
		return bytes.Join([][]byte{[]byte(hdrEnc), parts[1], parts[2]}, []byte("."))
	}

	var claims Claims

	// 1. Missing comma between header properties
	tokMissingComma := makeTokenWithRawHeader(`{"alg":"HS256" "typ":"JWT"}`)
	if err := v.Verify(tokMissingComma, now, &claims); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for missing comma in header, got %v", err)
	}

	// 2. Duplicate comma in header
	tokDupComma := makeTokenWithRawHeader(`{"alg":"HS256",,"typ":"JWT"}`)
	if err := v.Verify(tokDupComma, now, &claims); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for duplicate comma in header, got %v", err)
	}

	// 3. Trailing comma in header
	tokTrailingComma := makeTokenWithRawHeader(`{"alg":"HS256",}`)
	if err := v.Verify(tokTrailingComma, now, &claims); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for trailing comma in header, got %v", err)
	}

	// 4. Leading comma in header
	tokLeadingComma := makeTokenWithRawHeader(`{,"alg":"HS256"}`)
	if err := v.Verify(tokLeadingComma, now, &claims); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for leading comma in header, got %v", err)
	}

	// 5. Invalid colon separator
	tokColon := makeTokenWithRawHeader(`{"alg":"HS256":"typ":"JWT"}`)
	if err := v.Verify(tokColon, now, &claims); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for colon separator in header, got %v", err)
	}

	// 6. Non-quoted first key
	tokNonQuoted := makeTokenWithRawHeader(`{alg:"HS256"}`)
	if err := v.Verify(tokNonQuoted, now, &claims); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for non-quoted key, got %v", err)
	}
}

func TestES256_ScalarValidationAndSigningFailure(t *testing.T) {
	validKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// 1. Nil D scalar
	nilDKey := &ecdsa.PrivateKey{PublicKey: validKey.PublicKey, D: nil}
	if _, err := TryNewVerifier(nil, Options{Algorithm: AlgES256, ECDSAPrivateKey: nilDKey}); err == nil {
		t.Fatal("expected error for nil D scalar in TryNewVerifier")
	}

	// 2. Zero D scalar
	zeroDKey := &ecdsa.PrivateKey{PublicKey: validKey.PublicKey, D: big.NewInt(0)}
	if _, err := TryNewVerifier(nil, Options{Algorithm: AlgES256, ECDSAPrivateKey: zeroDKey}); err == nil {
		t.Fatal("expected error for D=0 scalar in TryNewVerifier")
	}

	// 3. D >= N scalar
	badDKey := &ecdsa.PrivateKey{PublicKey: validKey.PublicKey, D: validKey.Params().N}
	if _, err := TryNewVerifier(nil, Options{Algorithm: AlgES256, ECDSAPrivateKey: badDKey}); err == nil {
		t.Fatal("expected error for D>=N scalar in TryNewVerifier")
	}

	// 4. Signing failure returns ErrSigningFailed
	vBadES := &Verifier{alg: AlgES256, ecPriv: badDKey, sigEncodedLen: 86, maxPayloadSize: 4096}
	vBadES.pool.New = func() any { return vBadES.NewScratch() }
	if tok, err := vBadES.TrySign(nil, []byte(`{"sub":"1"}`)); !errors.Is(err, ErrSigningFailed) || tok != nil {
		t.Fatalf("expected (nil, ErrSigningFailed) on invalid scalar signing, got (%v, %v)", tok, err)
	}
}
