package zerojwt_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"

	zerojwt "github.com/KaikeGM/zerojwt/v2"
)

func TestZeroAllocations(t *testing.T) {
	if zerojwt.RaceDetectorEnabled {
		t.Skip("skipping zero-allocations verification under race detector (-race instruments memory and adds runtime allocations)")
	}
	secret := bytes.Repeat([]byte("s"), 32)
	v, err := zerojwt.New(secret)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	var tokBuf []byte
	tok, err := v.SignClaims(tokBuf, zerojwt.StandardClaims{
		Subject:   "user-12345",
		Username:  "alice",
		IssuedAt:  now,
		ExpiresAt: now + 3600,
	})
	if err != nil {
		t.Fatal(err)
	}

	var claims zerojwt.Claims

	// 1. Verify 0 allocs
	vAllocs := testing.AllocsPerRun(100, func() {
		if err := v.Verify(tok, now, &claims); err != nil {
			t.Fatal(err)
		}
	})
	if vAllocs != 0 {
		t.Fatalf("expected 0 allocs in Verify, got %v", vAllocs)
	}

	// 2. Sign 0 allocs (with pre-allocated buffer)
	signBuf := make([]byte, 0, 512)
	payload := []byte(`{"sub":"user-12345","username":"alice","iat":1700000000,"exp":1700003600}`)
	sAllocs := testing.AllocsPerRun(100, func() {
		res, err := v.Sign(signBuf[:0], payload)
		if err != nil || len(res) == 0 {
			t.Fatal(err)
		}
	})
	if sAllocs != 0 {
		t.Fatalf("expected 0 allocs in Sign, got %v", sAllocs)
	}

	// 3. SignClaims 0 allocs
	sc := zerojwt.StandardClaims{
		Subject:   "user-12345",
		Username:  "alice",
		IssuedAt:  now,
		ExpiresAt: now + 3600,
	}
	scAllocs := testing.AllocsPerRun(100, func() {
		res, err := v.SignClaims(signBuf[:0], sc)
		if err != nil || len(res) == 0 {
			t.Fatal(err)
		}
	})
	if scAllocs != 0 {
		t.Fatalf("expected 0 allocs in SignClaims, got %v", scAllocs)
	}

	// 4. SignBuilder 0 allocs
	sbAllocs := testing.AllocsPerRun(100, func() {
		b := v.NewSigner(signBuf[:0])
		b.SetSubject("user-12345")
		b.SetUsername("alice")
		b.SetExpiresAt(now + 3600)
		res, err := b.Sign()
		if err != nil || len(res) == 0 {
			t.Fatal(err)
		}
	})
	if sbAllocs != 0 {
		t.Fatalf("expected 0 allocs in SignBuilder, got %v", sbAllocs)
	}

	// 5. AppendEscapedJSON with dynamic 36-byte UUID: 0 allocs
	uuidDst := make([]byte, 0, 128)
	// Non-constant 36-byte string to test compiler escape analysis
	dynUUID := fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", 12345678, 1234, 5678, 9876, 543210987654)
	if len(dynUUID) != 36 {
		t.Fatalf("expected 36-byte UUID, got %d", len(dynUUID))
	}
	uuidAllocs := testing.AllocsPerRun(100, func() {
		res := zerojwt.AppendEscapedJSON(uuidDst[:0], dynUUID)
		if len(res) == 0 {
			t.Fatal("empty escaped json")
		}
	})
	if uuidAllocs != 0 {
		t.Fatalf("expected 0 allocs in AppendEscapedJSON with 36-byte string UUID, got %v", uuidAllocs)
	}

	// 6. EdDSA 0 allocs
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	vEd, err := zerojwt.NewEd25519Verifier(edPub, edPriv)
	if err != nil {
		t.Fatal(err)
	}
	edTok, err := vEd.SignClaims(signBuf[:0], sc)
	if err != nil {
		t.Fatal(err)
	}
	edVerifyAllocs := testing.AllocsPerRun(100, func() {
		if err := vEd.Verify(edTok, now, &claims); err != nil {
			t.Fatal(err)
		}
	})
	if edVerifyAllocs != 0 {
		t.Fatalf("expected 0 allocs in EdDSA Verify, got %v", edVerifyAllocs)
	}

	// 7. IterWithScratch and IterSplitWithScratch: 0 allocs
	st := v.NewScratch()
	iterAllocs := testing.AllocsPerRun(100, func() {
		for prop, err := range v.IterWithScratch(tok, now, st) {
			if err != nil {
				t.Fatal(err)
			}
			_ = prop
		}
	})
	if iterAllocs != 0 {
		t.Fatalf("expected 0 allocs in IterWithScratch, got %v", iterAllocs)
	}

	splitCut := len(tok) / 2
	head, tail := tok[:splitCut], tok[splitCut:]
	splitIterAllocs := testing.AllocsPerRun(100, func() {
		for prop, err := range v.IterSplitWithScratch(head, tail, now, st) {
			if err != nil {
				t.Fatal(err)
			}
			_ = prop
		}
	})
	if splitIterAllocs != 0 {
		t.Fatalf("expected 0 allocs in IterSplitWithScratch, got %v", splitIterAllocs)
	}

	// 8. EdDSA VerifySplit with large valid payload (~850B raw -> ~1175B encoded > 1024B) and oversized DoS payload: 0 allocs
	edSt := vEd.NewScratch()
	largeEdPayload := []byte(fmt.Sprintf(`{"sub":"%s","data":"%s","exp":%d}`,
		strings.Repeat("u", 200), strings.Repeat("x", 600), now+3600))
	largeEdTok, err := vEd.Sign(make([]byte, 0, 2048), largeEdPayload)
	if err != nil {
		t.Fatal(err)
	}
	edCut := len(largeEdTok) / 2
	edHead, edTail := largeEdTok[:edCut], largeEdTok[edCut:]
	edSplitAllocs := testing.AllocsPerRun(100, func() {
		if err := vEd.VerifySplitWithScratch(edHead, edTail, now, &claims, edSt); err != nil {
			t.Fatal(err)
		}
	})
	if edSplitAllocs != 0 {
		t.Fatalf("expected 0 allocs in EdDSA VerifySplitWithScratch on 850B payload, got %v", edSplitAllocs)
	}

	// Oversized unauthenticated EdDSA split payload must be rejected before stitching with 0 allocs (GO-2025-3488 / CWE-789)
	oversizedTail := append(bytes.Repeat([]byte("A"), 4096), []byte(".c2ln")...)
	edDoSAllocs := testing.AllocsPerRun(100, func() {
		if err := vEd.VerifySplitWithScratch(edHead, oversizedTail, now, &claims, edSt); err != zerojwt.ErrPayloadTooLarge {
			t.Fatalf("expected ErrPayloadTooLarge, got %v", err)
		}
	})
	if edDoSAllocs != 0 {
		t.Fatalf("expected 0 allocs rejecting oversized EdDSA split payload, got %v", edDoSAllocs)
	}
}

func BenchmarkVerifyHS256(b *testing.B) {
	secret := bytes.Repeat([]byte("s"), 32)
	v, err := zerojwt.New(secret)
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now().Unix()
	tok, err := v.SignClaims(nil, zerojwt.StandardClaims{
		Subject:   "1234567890",
		Username:  "john_doe",
		IssuedAt:  now,
		ExpiresAt: now + 3600,
	})
	if err != nil {
		b.Fatal(err)
	}
	var claims zerojwt.Claims
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = v.Verify(tok, now, &claims)
	}
}

func BenchmarkVerifyLargeSubject(b *testing.B) {
	secret := bytes.Repeat([]byte("s"), 32)
	v, err := zerojwt.New(secret)
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now().Unix()
	longSub := strings.Repeat("x", 250) // OIDC Core 1.0 §2 limit: <= 255
	tok, err := v.SignClaims(nil, zerojwt.StandardClaims{
		Subject:   longSub,
		Username:  "john_doe",
		IssuedAt:  now,
		ExpiresAt: now + 3600,
	})
	if err != nil {
		b.Fatal(err)
	}
	var claims zerojwt.Claims
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = v.Verify(tok, now, &claims)
	}
}

func BenchmarkSignHS256(b *testing.B) {
	secret := bytes.Repeat([]byte("s"), 32)
	v, err := zerojwt.New(secret)
	if err != nil {
		b.Fatal(err)
	}
	dst := make([]byte, 0, 512)
	payload := []byte(`{"sub":"1234567890","username":"john_doe","iat":1700000000,"exp":1700003600}`)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = v.Sign(dst[:0], payload)
	}
}

func BenchmarkSignClaims(b *testing.B) {
	secret := bytes.Repeat([]byte("s"), 32)
	v, err := zerojwt.New(secret)
	if err != nil {
		b.Fatal(err)
	}
	dst := make([]byte, 0, 512)
	sc := zerojwt.StandardClaims{
		Subject:   "1234567890",
		Username:  "john_doe",
		IssuedAt:  1700000000,
		ExpiresAt: 1700003600,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = v.SignClaims(dst[:0], sc)
	}
}

func BenchmarkSignBuilder(b *testing.B) {
	secret := bytes.Repeat([]byte("s"), 32)
	v, err := zerojwt.New(secret)
	if err != nil {
		b.Fatal(err)
	}
	dst := make([]byte, 0, 512)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		signer := v.NewSigner(dst[:0])
		signer.SetSubject("1234567890")
		signer.SetUsername("john_doe")
		signer.SetExpiresAt(1700003600)
		signer.SetClaimString("tenant", "acme-corp")
		_, _ = signer.Sign()
	}
}
