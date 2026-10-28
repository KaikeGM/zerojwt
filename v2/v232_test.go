package zerojwt

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"
)

func TestV232_VerifyStringHelpers(t *testing.T) {
	secret := []byte("secret-key-at-least-32-bytes-long!")
	v, err := New(secret)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	tokBytes, err := v.SignClaims(nil, StandardClaims{
		Subject:   "bob",
		ExpiresAt: now + 300,
	})
	if err != nil {
		t.Fatal(err)
	}
	tokStr := string(tokBytes)
	bearerStr := "Bearer " + tokStr

	var claims Claims

	// 1. VerifyString
	if err := v.VerifyString(tokStr, now, &claims); err != nil {
		t.Fatalf("VerifyString failed: %v", err)
	}
	if string(claims.Subject()) != "bob" {
		t.Fatalf("expected bob, got %s", string(claims.Subject()))
	}

	// 2. VerifyStringNow
	claims.Reset()
	if err := v.VerifyStringNow(tokStr, &claims); err != nil {
		t.Fatalf("VerifyStringNow failed: %v", err)
	}
	if string(claims.Subject()) != "bob" {
		t.Fatalf("expected bob, got %s", string(claims.Subject()))
	}

	// 3. VerifyStringWithScratch
	st := v.NewScratch()
	claims.Reset()
	if err := v.VerifyStringWithScratch(tokStr, now, &claims, st); err != nil {
		t.Fatalf("VerifyStringWithScratch failed: %v", err)
	}
	if string(claims.Subject()) != "bob" {
		t.Fatalf("expected bob, got %s", string(claims.Subject()))
	}

	// 4. VerifyBearerString
	claims.Reset()
	if err := v.VerifyBearerString(bearerStr, now, &claims); err != nil {
		t.Fatalf("VerifyBearerString failed: %v", err)
	}
	if string(claims.Subject()) != "bob" {
		t.Fatalf("expected bob, got %s", string(claims.Subject()))
	}

	// 5. VerifyBearerStringNow
	claims.Reset()
	if err := v.VerifyBearerStringNow(bearerStr, &claims); err != nil {
		t.Fatalf("VerifyBearerStringNow failed: %v", err)
	}
	if string(claims.Subject()) != "bob" {
		t.Fatalf("expected bob, got %s", string(claims.Subject()))
	}

	// 6. VerifyBearerStringWithScratch
	claims.Reset()
	if err := v.VerifyBearerStringWithScratch(bearerStr, now, &claims, st); err != nil {
		t.Fatalf("VerifyBearerStringWithScratch failed: %v", err)
	}
	if string(claims.Subject()) != "bob" {
		t.Fatalf("expected bob, got %s", string(claims.Subject()))
	}

	// 7. VerifyBearerWithScratch ([]byte)
	claims.Reset()
	if err := v.VerifyBearerWithScratch([]byte(bearerStr), now, &claims, st); err != nil {
		t.Fatalf("VerifyBearerWithScratch failed: %v", err)
	}
	if string(claims.Subject()) != "bob" {
		t.Fatalf("expected bob, got %s", string(claims.Subject()))
	}

	// Edge cases: empty string
	if err := v.VerifyString("", now, &claims); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for empty string, got %v", err)
	}
	if err := v.VerifyBearerString("invalid", now, &claims); !errors.Is(err, ErrMissingBearer) {
		t.Fatalf("expected ErrMissingBearer for invalid bearer, got %v", err)
	}
	if err := v.VerifyBearerWithScratch([]byte("invalid"), now, &claims, st); !errors.Is(err, ErrMissingBearer) {
		t.Fatalf("expected ErrMissingBearer for invalid bearer with scratch, got %v", err)
	}
}

func TestV232_ErrHeaderTooLarge(t *testing.T) {
	secret := []byte("secret-key-at-least-32-bytes-long!")
	v, err := New(secret)
	if err != nil {
		t.Fatal(err)
	}

	// Construct a token with header exceeding MaxHeaderSize (128 bytes)
	// Base64URL encoding of a 200-byte header
	largeHeader := bytes.Repeat([]byte(`{"alg":"HS256","padding":"`), 8) // > 128 bytes
	largeHeader = append(largeHeader, []byte(`"}`)...)
	encHdr := rawURLStrict.EncodeToString(largeHeader)

	fakeToken := []byte(encHdr + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0.dummy-signature")

	var claims Claims
	st := v.NewScratch()

	// Verify
	if err := v.Verify(fakeToken, time.Now().Unix(), &claims); !errors.Is(err, ErrHeaderTooLarge) {
		t.Fatalf("expected ErrHeaderTooLarge in Verify, got %v", err)
	}

	// VerifyWithScratch
	if err := v.VerifyWithScratch(fakeToken, time.Now().Unix(), &claims, st); !errors.Is(err, ErrHeaderTooLarge) {
		t.Fatalf("expected ErrHeaderTooLarge in VerifyWithScratch, got %v", err)
	}

	// VerifySplit
	dot := bytes.IndexByte(fakeToken, '.')
	if err := v.VerifySplit(fakeToken[:dot+1], fakeToken[dot+1:], time.Now().Unix(), &claims); !errors.Is(err, ErrHeaderTooLarge) {
		t.Fatalf("expected ErrHeaderTooLarge in VerifySplit, got %v", err)
	}

	// VerifySplitWithScratch
	if err := v.VerifySplitWithScratch(fakeToken[:dot+1], fakeToken[dot+1:], time.Now().Unix(), &claims, st); !errors.Is(err, ErrHeaderTooLarge) {
		t.Fatalf("expected ErrHeaderTooLarge in VerifySplitWithScratch, got %v", err)
	}
}

func TestV232_UpdateKeys_ZeroMemoryAndFinalizer(t *testing.T) {
	secret1 := []byte("secret-key-one-at-least-32-bytes-long!")
	secret2 := []byte("secret-key-two-at-least-32-bytes-long!")

	v, err := New(secret1, Options{ZeroMemory: true})
	if err != nil {
		t.Fatal(err)
	}

	// Update keys twice so the first keySet is dropped and collected
	newKeys := []Key{
		{ID: "k2", Secret: secret2},
	}
	if err := v.UpdateKeys(newKeys); err != nil {
		t.Fatal(err)
	}

	newKeys3 := []Key{
		{ID: "k2", Secret: secret2},
		{ID: "k3", Secret: secret1},
	}
	if err := v.UpdateKeys(newKeys3); err != nil {
		t.Fatal(err)
	}

	// Force GC to exercise runtime.SetFinalizer on the dropped keySet
	for i := 0; i < 10; i++ {
		runtime.GC()
		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
	}

	// Issuer with k2 as active key ID
	vIssuer, err := New(secret2, Options{ActiveKeyID: "k2"})
	if err != nil {
		t.Fatal(err)
	}

	// Verify verifier remains valid and works with k2
	now := time.Now().Unix()
	tok, err := vIssuer.SignClaims(nil, StandardClaims{
		Subject:   "charlie",
		ExpiresAt: now + 300,
	})
	if err != nil {
		t.Fatal(err)
	}

	var claims Claims
	if err := v.VerifyNow(tok, &claims); err != nil {
		t.Fatalf("VerifyNow failed after rotation: %v", err)
	}
	if string(claims.Subject()) != "charlie" {
		t.Fatalf("expected charlie, got %s", string(claims.Subject()))
	}
}

// TestV232_SplitConstants verifies the invariants between exported public constants
// and the internal Scratch struct memory layout.
// NOTE: If this test fails, you likely need to regenerate default.pgo and update
// the "Explicit Memory Bounds & Guarantees" section of both READMEs (README.md and README_pt-BR.md).
func TestV232_SplitConstants(t *testing.T) {
	var st Scratch
	if len(st.signArr) != MaxZeroAllocSplitSigningInput {
		t.Fatalf("MaxZeroAllocSplitSigningInput (%d) out of sync with len(Scratch.signArr) (%d)",
			MaxZeroAllocSplitSigningInput, len(st.signArr))
	}
	if len(st.hdrArr) != MaxHeaderSize {
		t.Fatalf("MaxHeaderSize (%d) out of sync with len(Scratch.hdrArr) (%d)",
			MaxHeaderSize, len(st.hdrArr))
	}
	if len(st.payloadArr) != MaxPayloadSize {
		t.Fatalf("MaxPayloadSize (%d) out of sync with len(Scratch.payloadArr) (%d)",
			MaxPayloadSize, len(st.payloadArr))
	}
	if MaxZeroAllocSplitPayloadSize != MaxPayloadSize {
		t.Fatalf("expected MaxZeroAllocSplitPayloadSize == %d, got %d", MaxPayloadSize, MaxZeroAllocSplitPayloadSize)
	}
}

func TestV232_Middleware_StringIntegration(t *testing.T) {
	secret := []byte("secret-key-at-least-32-bytes-long!")
	v, err := New(secret)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	tok, err := v.SignClaims(nil, StandardClaims{
		Subject:   "diana",
		ExpiresAt: now + 300,
	})
	if err != nil {
		t.Fatal(err)
	}

	called := false
	handler := v.ProtectFunc(func(w http.ResponseWriter, r *http.Request, claims *Claims) {
		called = true
		if string(claims.Subject()) != "diana" {
			t.Fatalf("expected diana, got %s", string(claims.Subject()))
		}
		w.WriteHeader(http.StatusOK)
	})

	// Valid Authorization header
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+string(tok))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("expected OK, got code %d, called %v", rec.Code, called)
	}

	// Middleware standard handler
	stdCalled := false
	stdHandler := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stdCalled = true
		claims := FromContext(r.Context())
		if claims == nil || string(claims.Subject()) != "diana" {
			t.Fatalf("expected claims in context with diana")
		}
		w.WriteHeader(http.StatusOK)
	}))

	rec2 := httptest.NewRecorder()
	stdHandler.ServeHTTP(rec2, req)
	if !stdCalled || rec2.Code != http.StatusOK {
		t.Fatalf("expected OK from Middleware, got code %d", rec2.Code)
	}
}
