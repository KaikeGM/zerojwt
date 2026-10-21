package zerojwt_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	zerojwt "github.com/KaikeGM/zerojwt/v2"
)

func TestComprehensiveEdgeCases(t *testing.T) {
	now := time.Now().Unix()
	secret := bytes.Repeat([]byte("s"), 32)
	v, err := zerojwt.New(secret, zerojwt.Options{
		ExpectedIssuer:   "auth.zerojwt.io",
		ExpectedAudience: "api.zerojwt.io",
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Verifier Getters & String
	if v.Algorithm() != zerojwt.AlgHS256 {
		t.Fatalf("expected AlgHS256, got %v", v.Algorithm())
	}
	if v.Algorithm().String() != "HS256" {
		t.Fatalf("expected 'HS256', got %q", v.Algorithm().String())
	}
	if v.MaxHeaderSize() != zerojwt.MaxHeaderSize {
		t.Fatalf("expected default max header size %d, got %d", zerojwt.MaxHeaderSize, v.MaxHeaderSize())
	}
	if v.MaxPayloadSize() != zerojwt.MaxPayloadSize {
		t.Fatalf("expected default max payload size %d, got %d", zerojwt.MaxPayloadSize, v.MaxPayloadSize())
	}

	// 2. NewWithOptions and NewSecureVerifier aliases
	vOpt, err := zerojwt.NewWithOptions(secret, zerojwt.Options{})
	if err != nil || vOpt == nil {
		t.Fatalf("NewWithOptions failed: %v", err)
	}
	vSec, err := zerojwt.NewSecureVerifier(secret)
	if err != nil || vSec == nil {
		t.Fatalf("NewSecureVerifier failed: %v", err)
	}

	// 3. Claims Methods
	var c zerojwt.Claims
	c.Reset()
	c.Clear()
	if len(c.Subject()) != 0 || len(c.Username()) != 0 || len(c.Issuer()) != 0 || len(c.Audience()) != 0 || len(c.JTI()) != 0 {
		t.Fatal("expected empty slices for empty claims")
	}

	// 4. Scratch Clear & Memclr
	st := v.NewScratch()
	st.Clear()

	// 5. SignBuilder all setters
	dst := make([]byte, 0, 1024)
	b := v.NewSignerWithScratch(dst, st)
	b.SetSubject("sub-str")
	b.SetUsername("user-str")
	b.SetIssuer("auth.zerojwt.io")
	b.SetAudience("api.zerojwt.io")
	b.SetJTI("jti-str")
	b.SetIssuedAt(now)
	b.SetExpiresAt(now + 3600)
	b.SetNotBefore(now - 10)
	b.SetClaimString("custom_str", "hello")
	b.SetClaimBytes("custom_bytes", []byte("world"))
	b.SetClaimInt("custom_int", 999)
	b.SetClaimBool("custom_bool_t", true)
	b.SetClaimBool("custom_bool_f", false)
	b.SetClaimRawJSON("custom_raw", []byte(`{"nested":true}`))

	tokBuilder, err := b.Sign()
	if err != nil {
		t.Fatalf("SignBuilder Sign failed: %v", err)
	}
	b.Discard() // test idempotent discard

	// Verify into Claims
	err = v.Verify(tokBuilder, now, &c)
	if err != nil {
		t.Fatalf("Verify token from builder failed: %v", err)
	}
	if string(c.Subject()) != "sub-str" || string(c.Username()) != "user-str" {
		t.Fatalf("claims mismatch: sub=%s user=%s", c.Subject(), c.Username())
	}
	if string(c.Issuer()) != "auth.zerojwt.io" || string(c.Audience()) != "api.zerojwt.io" {
		t.Fatalf("iss/aud mismatch: iss=%s aud=%s", c.Issuer(), c.Audience())
	}
	if string(c.JTI()) != "jti-str" {
		t.Fatalf("jti mismatch: %s", c.JTI())
	}

	// Builder 2 with bytes setters
	b2 := v.NewSigner(nil)
	b2.SetSubjectBytes([]byte("sub-bytes"))
	b2.SetUsernameBytes([]byte("user-bytes"))
	b2.SetIssuerBytes([]byte("auth.zerojwt.io"))
	b2.SetAudienceBytes([]byte("api.zerojwt.io"))
	b2.SetJTIBytes([]byte("jti-bytes"))
	b2.SetExpiresAt(now + 3600)
	tokBuilder2, err := b2.Sign()
	if err != nil {
		t.Fatalf("SignBuilder b2 Sign failed: %v", err)
	}
	err = v.Verify(tokBuilder2, now, &c)
	if err != nil {
		t.Fatalf("Verify token from builder 2 failed: %v", err)
	}
	if string(c.Subject()) != "sub-bytes" || string(c.Username()) != "user-bytes" {
		t.Fatalf("claims mismatch in b2: sub=%s user=%s", c.Subject(), c.Username())
	}
	if string(c.JTI()) != "jti-bytes" {
		t.Fatalf("jti mismatch in b2: %s", c.JTI())
	}

	// SignBuilder nil scratch error
	emptyB := zerojwt.SignBuilder{}
	if _, err := emptyB.Sign(); !errors.Is(err, zerojwt.ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload on nil scratch, got %v", err)
	}

	// SignBuilder payload too large
	tinyV, err := zerojwt.New(secret, zerojwt.Options{
		MaxPayloadSize:   20,
		ExpectedIssuer:   "auth.zerojwt.io",
		ExpectedAudience: "api.zerojwt.io",
	})
	if err != nil {
		t.Fatal(err)
	}
	tinyB := tinyV.NewSigner(nil)
	tinyB.SetClaimString("long", "very_long_string_that_exceeds_twenty_bytes")
	if _, err := tinyB.Sign(); !errors.Is(err, zerojwt.ErrPayloadTooLarge) {
		t.Fatalf("expected ErrPayloadTooLarge, got %v", err)
	}

	// 6. VerifyBearer & Middleware
	bearerTok := append([]byte("Bearer "), tokBuilder...)
	err = v.VerifyBearer(bearerTok, now, &c)
	if err != nil {
		t.Fatalf("VerifyBearer failed: %v", err)
	}
	if err := v.VerifyBearer([]byte("InvalidPrefix token"), now, &c); !errors.Is(err, zerojwt.ErrMissingBearer) {
		t.Fatalf("expected ErrMissingBearer, got %v", err)
	}

	// ProtectFunc
	handler := v.ProtectFunc(func(w http.ResponseWriter, r *http.Request, claims *zerojwt.Claims) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(claims.Subject())
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", string(bearerTok))
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "sub-str" {
		t.Fatalf("ProtectFunc failed: code=%d body=%s", rec.Code, rec.Body.String())
	}

	// ProtectFunc short auth
	reqBad := httptest.NewRequest(http.MethodGet, "/", nil)
	reqBad.Header.Set("Authorization", "Bear")
	recBad := httptest.NewRecorder()
	handler(recBad, reqBad)
	if recBad.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for short auth, got %d", recBad.Code)
	}

	// ProtectFunc invalid token
	reqBadTok := httptest.NewRequest(http.MethodGet, "/", nil)
	reqBadTok.Header.Set("Authorization", "Bearer invalid.token.value")
	recBadTok := httptest.NewRecorder()
	handler(recBadTok, reqBadTok)
	if recBadTok.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad token, got %d", recBadTok.Code)
	}

	// Middleware
	mw := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := zerojwt.ClaimsFromContext(r.Context())
		if !ok || claims == nil {
			http.Error(w, "no claims", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(claims.Subject())
	}))
	recMW := httptest.NewRecorder()
	mw.ServeHTTP(recMW, req)
	if recMW.Code != http.StatusOK || recMW.Body.String() != "sub-str" {
		t.Fatalf("Middleware failed: code=%d body=%s", recMW.Code, recMW.Body.String())
	}

	// Middleware short auth
	recMWBad := httptest.NewRecorder()
	mw.ServeHTTP(recMWBad, reqBad)
	if recMWBad.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for short auth in middleware, got %d", recMWBad.Code)
	}

	// Middleware invalid token
	recMWBadTok := httptest.NewRecorder()
	mw.ServeHTTP(recMWBadTok, reqBadTok)
	if recMWBadTok.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad token in middleware, got %d", recMWBadTok.Code)
	}

	// ClaimsFromContext when missing
	if _, ok := zerojwt.ClaimsFromContext(context.Background()); ok {
		t.Fatal("expected false for ClaimsFromContext with empty context")
	}

	// 7. VerifyLarge compatibility
	err = v.VerifyLarge(tokBuilder, now, &c)
	if err != nil {
		t.Fatalf("VerifyLarge failed: %v", err)
	}
	err = v.VerifyLargeWithScratch(tokBuilder, now, &c, st)
	if err != nil {
		t.Fatalf("VerifyLargeWithScratch failed: %v", err)
	}

	// 8. VerifyCustom compatibility
	var customKeys []string
	err = v.VerifyCustom(tokBuilder, now, func(key, val []byte, isStr bool) bool {
		customKeys = append(customKeys, string(key))
		return true
	})
	if err != nil || len(customKeys) == 0 {
		t.Fatalf("VerifyCustom failed: %v (keys: %v)", err, customKeys)
	}

	// 9. TrySign and TrySignClaims aliases
	tokTry, err := v.TrySign(nil, []byte(`{"sub":"try","exp":`+strconv.FormatInt(now+1000, 10)+`,"iss":"auth.zerojwt.io","aud":"api.zerojwt.io"}`))
	if err != nil {
		t.Fatalf("TrySign failed: %v", err)
	}
	err = v.Verify(tokTry, now, &c)
	if err != nil || string(c.Subject()) != "try" {
		t.Fatalf("Verify TrySign failed: %v", err)
	}

	tokTryClaims, err := v.TrySignClaims(nil, []byte("tryuser"), []byte("uname"), now, now+1000)
	if err != nil {
		t.Fatalf("TrySignClaims failed: %v", err)
	}
	err = v.Verify(tokTryClaims, now, &c)
	if err != nil || string(c.Subject()) != "tryuser" {
		t.Fatalf("Verify TrySignClaims failed: %v", err)
	}

	// 10. Destroy & ZeroMemory
	vDestroy, err := zerojwt.New(secret, zerojwt.Options{ZeroMemory: true})
	if err != nil {
		t.Fatal(err)
	}
	if !vDestroy.CanSign() {
		t.Fatal("expected CanSign to be true before Destroy")
	}
	vDestroy.Destroy()
	vDestroy.Destroy() // idempotent
	if vDestroy.CanSign() {
		t.Fatal("expected CanSign to be false after Destroy")
	}
	if _, err := vDestroy.Sign(nil, []byte("{}")); !errors.Is(err, zerojwt.ErrVerifierDestroyed) {
		t.Fatalf("expected ErrVerifierDestroyed on Sign, got %v", err)
	}
	if _, err := vDestroy.SignClaims(nil, zerojwt.StandardClaims{}); !errors.Is(err, zerojwt.ErrVerifierDestroyed) {
		t.Fatalf("expected ErrVerifierDestroyed on SignClaims, got %v", err)
	}
	if err := vDestroy.Verify(tokBuilder, now, &c); !errors.Is(err, zerojwt.ErrVerifierDestroyed) {
		t.Fatalf("expected ErrVerifierDestroyed on Verify, got %v", err)
	}
}

func TestAllAlgorithmsAndKeyRotation(t *testing.T) {
	now := time.Now().Unix()
	var c zerojwt.Claims

	// --- HS384 ---
	sec384 := bytes.Repeat([]byte("3"), 48)
	v384, err := zerojwt.New(sec384, zerojwt.Options{Algorithm: zerojwt.AlgHS384})
	if err != nil {
		t.Fatalf("New HS384 failed: %v", err)
	}
	tok384, err := v384.SignClaims(nil, zerojwt.StandardClaims{
		Subject:   "user384",
		ExpiresAt: now + 3600,
	})
	if err != nil {
		t.Fatalf("SignClaims HS384 failed: %v", err)
	}
	if err := v384.Verify(tok384, now, &c); err != nil {
		t.Fatalf("Verify HS384 failed: %v", err)
	}
	if string(c.Subject()) != "user384" {
		t.Fatalf("HS384 subject mismatch: %s", c.Subject())
	}

	// --- HS512 ---
	sec512 := bytes.Repeat([]byte("5"), 64)
	v512, err := zerojwt.New(sec512, zerojwt.Options{Algorithm: zerojwt.AlgHS512})
	if err != nil {
		t.Fatalf("New HS512 failed: %v", err)
	}
	tok512, err := v512.SignClaims(nil, zerojwt.StandardClaims{
		Subject:   "user512",
		ExpiresAt: now + 3600,
	})
	if err != nil {
		t.Fatalf("SignClaims HS512 failed: %v", err)
	}
	if err := v512.Verify(tok512, now, &c); err != nil {
		t.Fatalf("Verify HS512 failed: %v", err)
	}
	if string(c.Subject()) != "user512" {
		t.Fatalf("HS512 subject mismatch: %s", c.Subject())
	}

	// --- EdDSA ---
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	vEd, err := zerojwt.NewEd25519Verifier(edPub, edPriv)
	if err != nil {
		t.Fatalf("NewEd25519Verifier failed: %v", err)
	}
	tokEd, err := vEd.SignClaims(nil, zerojwt.StandardClaims{
		Subject:   "userEd",
		ExpiresAt: now + 3600,
	})
	if err != nil {
		t.Fatalf("SignClaims EdDSA failed: %v", err)
	}
	if err := vEd.Verify(tokEd, now, &c); err != nil {
		t.Fatalf("Verify EdDSA failed: %v", err)
	}
	if string(c.Subject()) != "userEd" {
		t.Fatalf("EdDSA subject mismatch: %s", c.Subject())
	}

	// EdDSA verify-only node
	vEdVerifyOnly, err := zerojwt.NewEd25519Verifier(edPub, nil)
	if err != nil {
		t.Fatal(err)
	}
	if vEdVerifyOnly.CanSign() {
		t.Fatal("expected CanSign to be false for verify-only EdDSA node")
	}
	if _, err := vEdVerifyOnly.Sign(nil, []byte("{}")); !errors.Is(err, zerojwt.ErrNoSigningKey) {
		t.Fatalf("expected ErrNoSigningKey, got %v", err)
	}
	if err := vEdVerifyOnly.Verify(tokEd, now, &c); err != nil {
		t.Fatalf("Verify on verify-only EdDSA failed: %v", err)
	}

	// --- ES256 ---
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	vEc, err := zerojwt.NewES256Verifier(&ecPriv.PublicKey, ecPriv)
	if err != nil {
		t.Fatalf("NewES256Verifier failed: %v", err)
	}
	tokEc, err := vEc.SignClaims(nil, zerojwt.StandardClaims{
		Subject:   "userES256",
		ExpiresAt: now + 3600,
	})
	if err != nil {
		t.Fatalf("SignClaims ES256 failed: %v", err)
	}
	if err := vEc.Verify(tokEc, now, &c); err != nil {
		t.Fatalf("Verify ES256 failed: %v", err)
	}
	if string(c.Subject()) != "userES256" {
		t.Fatalf("ES256 subject mismatch: %s", c.Subject())
	}

	// ES256 verify-only node
	vEcVerifyOnly, err := zerojwt.NewES256Verifier(&ecPriv.PublicKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if vEcVerifyOnly.CanSign() {
		t.Fatal("expected CanSign to be false for verify-only ES256 node")
	}
	if err := vEcVerifyOnly.Verify(tokEc, now, &c); err != nil {
		t.Fatalf("Verify on verify-only ES256 failed: %v", err)
	}

	// --- Key Rotation with "kid" ---
	key1 := bytes.Repeat([]byte("1"), 32)
	key2 := bytes.Repeat([]byte("2"), 32)
	vRot, err := zerojwt.New(key1, zerojwt.Options{
		ActiveKeyID: "key-1",
		Keys: []zerojwt.Key{
			{ID: "key-1", Secret: key1},
			{ID: "key-2", Secret: key2},
		},
	})
	if err != nil {
		t.Fatalf("New with Keys failed: %v", err)
	}
	tokRot1, err := vRot.SignClaims(nil, zerojwt.StandardClaims{
		Subject:   "rotated-sub",
		ExpiresAt: now + 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := vRot.Verify(tokRot1, now, &c); err != nil {
		t.Fatalf("Verify rotated key failed: %v", err)
	}

	// Token with unknown key ID
	hdrUnknown := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT","kid":"unknown-9"}`))
	tokUnknownKid := []byte(hdrUnknown + ".eyJzdWIiOiJyb3RhdGVkLXN1YiIsImV4cCI6MTkwMDAwMDAwMH0.sig")
	if err := vRot.Verify(tokUnknownKid, now, &c); !errors.Is(err, zerojwt.ErrUnknownKeyID) {
		t.Fatalf("expected ErrUnknownKeyID, got %v", err)
	}
}

func TestValidationErrorsAndBadConfigs(t *testing.T) {
	// Unsupported algorithm
	_, err := zerojwt.New(bytes.Repeat([]byte("a"), 32), zerojwt.Options{Algorithm: zerojwt.Algorithm("NONE")})
	if !errors.Is(err, zerojwt.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for unsupported algorithm, got %v", err)
	}

	// Short secret HS384 / HS512
	_, err = zerojwt.New(bytes.Repeat([]byte("a"), 47), zerojwt.Options{Algorithm: zerojwt.AlgHS384})
	if !errors.Is(err, zerojwt.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for short HS384 secret, got %v", err)
	}
	_, err = zerojwt.New(bytes.Repeat([]byte("a"), 63), zerojwt.Options{Algorithm: zerojwt.AlgHS512})
	if !errors.Is(err, zerojwt.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for short HS512 secret, got %v", err)
	}

	// Empty HMAC secret without Keys
	_, err = zerojwt.New(nil)
	if !errors.Is(err, zerojwt.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for empty HMAC secret, got %v", err)
	}

	// Keys with empty ID
	_, err = zerojwt.New(bytes.Repeat([]byte("a"), 32), zerojwt.Options{
		Keys: []zerojwt.Key{{ID: ""}},
	})
	if !errors.Is(err, zerojwt.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for Keys with empty ID, got %v", err)
	}

	// Keys with duplicate ID
	_, err = zerojwt.New(bytes.Repeat([]byte("a"), 32), zerojwt.Options{
		Keys: []zerojwt.Key{
			{ID: "k1", Secret: bytes.Repeat([]byte("a"), 32)},
			{ID: "k1", Secret: bytes.Repeat([]byte("b"), 32)},
		},
	})
	if !errors.Is(err, zerojwt.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for duplicate key ID, got %v", err)
	}

	// Keys with empty secret for HMAC
	_, err = zerojwt.New(bytes.Repeat([]byte("a"), 32), zerojwt.Options{
		Keys: []zerojwt.Key{{ID: "k1", Secret: nil}},
	})
	if !errors.Is(err, zerojwt.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for Keys with empty secret, got %v", err)
	}

	// Keys with short secret for HMAC when strict
	_, err = zerojwt.New(bytes.Repeat([]byte("a"), 32), zerojwt.Options{
		Keys: []zerojwt.Key{{ID: "k1", Secret: []byte("short")}},
	})
	if !errors.Is(err, zerojwt.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for Keys with short secret, got %v", err)
	}

	// Keys with wrong Ed25519 key size
	_, err = zerojwt.New(nil, zerojwt.Options{
		Algorithm: zerojwt.AlgEdDSA,
		Keys:      []zerojwt.Key{{ID: "k1", Ed25519Public: []byte("short")}},
	})
	if !errors.Is(err, zerojwt.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for wrong Ed25519 key size in Keys, got %v", err)
	}

	// Keys with non-P256 ECDSA public key
	p384Key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, err = zerojwt.New(nil, zerojwt.Options{
		Algorithm: zerojwt.AlgES256,
		Keys:      []zerojwt.Key{{ID: "k1", ECDSAPublic: &p384Key.PublicKey}},
	})
	if !errors.Is(err, zerojwt.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for non P-256 ECDSA public key in Keys, got %v", err)
	}

	// EdDSA missing key
	_, err = zerojwt.New(nil, zerojwt.Options{Algorithm: zerojwt.AlgEdDSA})
	if !errors.Is(err, zerojwt.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for missing EdDSA key, got %v", err)
	}

	// EdDSA wrong pub key size
	_, err = zerojwt.New(nil, zerojwt.Options{Algorithm: zerojwt.AlgEdDSA, Ed25519PublicKey: []byte("short")})
	if !errors.Is(err, zerojwt.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for wrong EdDSA pub key size, got %v", err)
	}

	// EdDSA wrong priv key size
	_, err = zerojwt.New(nil, zerojwt.Options{Algorithm: zerojwt.AlgEdDSA, Ed25519PrivateKey: []byte("short")})
	if !errors.Is(err, zerojwt.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for wrong EdDSA priv key size, got %v", err)
	}

	// ES256 missing key
	_, err = zerojwt.New(nil, zerojwt.Options{Algorithm: zerojwt.AlgES256})
	if !errors.Is(err, zerojwt.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for missing ES256 key, got %v", err)
	}

	// ES256 wrong public key curve
	_, err = zerojwt.New(nil, zerojwt.Options{Algorithm: zerojwt.AlgES256, ECDSAPublicKey: &p384Key.PublicKey})
	if !errors.Is(err, zerojwt.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for non P-256 ES256 pub key, got %v", err)
	}

	// ES256 wrong private key curve
	_, err = zerojwt.New(nil, zerojwt.Options{Algorithm: zerojwt.AlgES256, ECDSAPrivateKey: p384Key})
	if !errors.Is(err, zerojwt.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for non P-256 ES256 priv key, got %v", err)
	}

	// ES256 private key scalar D <= 0 or D >= N
	p256Key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	badDKey := *p256Key
	badDKey.D = big.NewInt(0)
	_, err = zerojwt.New(nil, zerojwt.Options{Algorithm: zerojwt.AlgES256, ECDSAPrivateKey: &badDKey})
	if !errors.Is(err, zerojwt.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for ES256 private key with D=0, got %v", err)
	}
	badDKey.D = elliptic.P256().Params().N
	_, err = zerojwt.New(nil, zerojwt.Options{Algorithm: zerojwt.AlgES256, ECDSAPrivateKey: &badDKey})
	if !errors.Is(err, zerojwt.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for ES256 private key with D>=N, got %v", err)
	}

	// Leeway < 1s
	_, err = zerojwt.New(bytes.Repeat([]byte("a"), 32), zerojwt.Options{Leeway: 500 * time.Millisecond})
	if !errors.Is(err, zerojwt.ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for leeway < 1s, got %v", err)
	}
}

func TestSignClaimsFieldBoundaries(t *testing.T) {
	v, err := zerojwt.New(bytes.Repeat([]byte("a"), 32))
	if err != nil {
		t.Fatal(err)
	}

	// Subject empty
	_, err = v.SignClaims(nil, zerojwt.StandardClaims{Subject: "", ExpiresAt: 100})
	if !errors.Is(err, zerojwt.ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for empty subject, got %v", err)
	}

	// Subject > 256
	_, err = v.SignClaims(nil, zerojwt.StandardClaims{Subject: strings.Repeat("s", 257), ExpiresAt: 100})
	if !errors.Is(err, zerojwt.ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for subject > 256, got %v", err)
	}

	// Username > 128
	_, err = v.SignClaims(nil, zerojwt.StandardClaims{Subject: "sub", Username: strings.Repeat("u", 129), ExpiresAt: 100})
	if !errors.Is(err, zerojwt.ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for username > 128, got %v", err)
	}

	// Issuer > 256
	_, err = v.SignClaims(nil, zerojwt.StandardClaims{Subject: "sub", Issuer: strings.Repeat("i", 257), ExpiresAt: 100})
	if !errors.Is(err, zerojwt.ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for issuer > 256, got %v", err)
	}

	// Audience > 256
	_, err = v.SignClaims(nil, zerojwt.StandardClaims{Subject: "sub", Audience: strings.Repeat("a", 257), ExpiresAt: 100})
	if !errors.Is(err, zerojwt.ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for audience > 256, got %v", err)
	}

	// JTI > 64
	_, err = v.SignClaims(nil, zerojwt.StandardClaims{Subject: "sub", JTI: strings.Repeat("j", 65), ExpiresAt: 100})
	if !errors.Is(err, zerojwt.ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for JTI > 64, got %v", err)
	}

	// Payload too large
	smallV, _ := zerojwt.New(bytes.Repeat([]byte("a"), 32), zerojwt.Options{MaxPayloadSize: 20})
	_, err = smallV.SignClaims(nil, zerojwt.StandardClaims{Subject: "subject-that-fits-standard-but-exceeds-small-max-payload", ExpiresAt: 100})
	if !errors.Is(err, zerojwt.ErrPayloadTooLarge) {
		t.Fatalf("expected ErrPayloadTooLarge, got %v", err)
	}
}

func TestMalformedTokensAndHeaders(t *testing.T) {
	secret := bytes.Repeat([]byte("s"), 32)
	v, err := zerojwt.New(secret)
	if err != nil {
		t.Fatal(err)
	}
	var claims zerojwt.Claims
	now := time.Now().Unix()

	// Newlines in token
	if err := v.Verify([]byte("token\nwith\nnewlines"), now, &claims); !errors.Is(err, zerojwt.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for token with LF, got %v", err)
	}
	if err := v.Verify([]byte("token\rwith\rcr"), now, &claims); !errors.Is(err, zerojwt.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for token with CR, got %v", err)
	}

	// Wrong dot counts
	if err := v.Verify([]byte("nodots"), now, &claims); !errors.Is(err, zerojwt.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for no dots, got %v", err)
	}
	if err := v.Verify([]byte("one.dot"), now, &claims); !errors.Is(err, zerojwt.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for one dot, got %v", err)
	}
	if err := v.Verify([]byte("four.dots.in.the.token"), now, &claims); !errors.Is(err, zerojwt.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for four dots, got %v", err)
	}
	if err := v.Verify([]byte(".empty.header"), now, &claims); !errors.Is(err, zerojwt.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for empty header, got %v", err)
	}
	if err := v.Verify([]byte("header..empty_payload"), now, &claims); !errors.Is(err, zerojwt.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for empty payload, got %v", err)
	}
	if err := v.Verify([]byte("header.payload."), now, &claims); !errors.Is(err, zerojwt.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for empty signature, got %v", err)
	}

	// Bad base64
	if err := v.Verify([]byte("bad%hdr.bad%payload.bad%sig"), now, &claims); err == nil {
		t.Fatal("expected error on bad base64")
	}

	// Critical header rejection (RFC 7515 §4.1.11)
	critHdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","crit":["b64"]}`))
	critTok := critHdr + ".eyJzdWIiOiIxMjMiLCJleHAiOjE5MDAwMDAwMDB9.invalidsig"
	if err := v.Verify([]byte(critTok), now, &claims); !errors.Is(err, zerojwt.ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for crit header, got %v", err)
	}

	// Invalid header syntax: not object, starting without quote, comma without quote
	badHdr1 := base64.RawURLEncoding.EncodeToString([]byte(`"not_an_object"`)) + ".eyJzdWIiOiIxMjMifQ.sig"
	if err := v.Verify([]byte(badHdr1), now, &claims); !errors.Is(err, zerojwt.ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for non-object header, got %v", err)
	}

	badHdr2 := base64.RawURLEncoding.EncodeToString([]byte(`{123:"val"}`)) + ".eyJzdWIiOiIxMjMifQ.sig"
	if err := v.Verify([]byte(badHdr2), now, &claims); !errors.Is(err, zerojwt.ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for header not starting with quote, got %v", err)
	}

	badHdr3 := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256", 123:"val"}`)) + ".eyJzdWIiOiIxMjMifQ.sig"
	if err := v.Verify([]byte(badHdr3), now, &claims); !errors.Is(err, zerojwt.ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for comma without quote in header, got %v", err)
	}

	badHdr4 := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"NOT_JWT"}`)) + ".eyJzdWIiOiIxMjMifQ.sig"
	if err := v.Verify([]byte(badHdr4), now, &claims); !errors.Is(err, zerojwt.ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for invalid typ, got %v", err)
	}
}

func TestScannerUnescapeAndParsing(t *testing.T) {
	// Unescape in-place with unicode, surrogates, and control chars
	input := []byte(`Hello\nWorld\t\"Escaped\"\u0041\uD83D\uDE00\/`)
	unescaped := zerojwt.UnescapeJSONInPlace(input)
	if !strings.Contains(string(unescaped), "Hello\nWorld\t\"Escaped\"A😀/") {
		t.Fatalf("unexpected unescaped result: %s", string(unescaped))
	}

	// Invalid unicode surrogates fallback
	badSurrogate := []byte(`\uD800\u0041\u123z\u`)
	_ = zerojwt.UnescapeJSONInPlace(badSurrogate)

	// AppendEscapedJSONString
	res := zerojwt.AppendEscapedJSONString(nil, []byte("test\r\n\t\"\\"))
	if string(res) != `"test\r\n\t\"\\"` {
		t.Fatalf("unexpected escaped string: %s", string(res))
	}

	// ParseJSONNumber edge cases
	if _, ok := zerojwt.ParseJSONNumber([]byte("")); ok {
		t.Fatal("expected false for empty number")
	}
	if _, ok := zerojwt.ParseJSONNumber([]byte("-")); ok {
		t.Fatal("expected false for solitary '-'")
	}
	if _, ok := zerojwt.ParseJSONNumber([]byte("abc")); ok {
		t.Fatal("expected false for non-numeric")
	}
	if n, ok := zerojwt.ParseJSONNumber([]byte("-123.456e+2")); !ok || int(n) != -12345 {
		t.Fatalf("expected -12345, got %v (ok=%v)", n, ok)
	}
	if n, ok := zerojwt.ParseJSONNumber([]byte("123.456e-2")); !ok || n < 1.23 || n > 1.24 {
		t.Fatalf("expected ~1.23456, got %v (ok=%v)", n, ok)
	}
	if _, ok := zerojwt.ParseJSONNumber([]byte("123.")); ok {
		t.Fatal("expected false for trailing dot")
	}
	if _, ok := zerojwt.ParseJSONNumber([]byte("123e")); ok {
		t.Fatal("expected false for trailing e")
	}
	if _, ok := zerojwt.ParseJSONNumber([]byte("123.456extra")); ok {
		t.Fatal("expected false for trailing characters")
	}

	// ParsePositiveInt edge cases
	if _, ok := zerojwt.ParsePositiveInt([]byte("")); ok {
		t.Fatal("expected false for empty")
	}
	if _, ok := zerojwt.ParsePositiveInt([]byte("0")); ok {
		t.Fatal("expected false for 0")
	}
	if _, ok := zerojwt.ParsePositiveInt([]byte("123a")); ok {
		t.Fatal("expected false for non-digits")
	}
	if _, ok := zerojwt.ParsePositiveInt([]byte("99999999999999999999")); ok { // > 19 digits
		t.Fatal("expected false for > 19 digits")
	}
	if id, ok := zerojwt.ParsePositiveInt([]byte("123456789")); !ok || id != 123456789 {
		t.Fatalf("expected 123456789, got %d", id)
	}
}
