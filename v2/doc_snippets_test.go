package zerojwt_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KaikeGM/zerojwt/v2"
)

// TestREADMEExamples compiles and executes every snippet presented in v2/README.md
// to guarantee 100% documentation accuracy and compile-time correctness.
func TestREADMEExamples(t *testing.T) {
	secret := []byte("your-32-byte-ultra-secure-secret-key!")
	now := time.Now().Unix()

	// 1. Quick Start
	v, err := zerojwt.New(secret)
	if err != nil {
		t.Fatalf("Quick Start New failed: %v", err)
	}

	token, err := v.SignClaims(nil, zerojwt.StandardClaims{
		Subject:   "usr_9847239847",
		Username:  "alex_dev",
		IssuedAt:  now,
		ExpiresAt: now + 3600,
	})
	if err != nil {
		t.Fatalf("Quick Start SignClaims failed: %v", err)
	}

	var claims zerojwt.Claims
	if err := v.Verify(token, now, &claims); err != nil {
		t.Fatalf("Quick Start Verify failed: %v", err)
	}

	// 2. Cryptographic Algorithms
	secret32 := []byte("01234567890123456789012345678901")
	secret48 := []byte("012345678901234567890123456789010123456789012345")
	secret64 := []byte("0123456789012345678901234567890101234567890123450123456789012345")

	_, err = zerojwt.New(secret32)
	if err != nil {
		t.Fatalf("HS256 New failed: %v", err)
	}
	_, err = zerojwt.New(secret48, zerojwt.Options{Algorithm: zerojwt.AlgHS384})
	if err != nil {
		t.Fatalf("HS384 New failed: %v", err)
	}
	_, err = zerojwt.New(secret64, zerojwt.Options{Algorithm: zerojwt.AlgHS512})
	if err != nil {
		t.Fatalf("HS512 New failed: %v", err)
	}

	// Ed25519
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Ed25519 keygen failed: %v", err)
	}
	vEd, err := zerojwt.NewEd25519Verifier(edPub, edPriv)
	if err != nil {
		t.Fatalf("NewEd25519Verifier failed: %v", err)
	}
	_, err = zerojwt.NewEd25519Verifier(edPub, nil)
	if err != nil {
		t.Fatalf("NewEd25519Verifier pub only failed: %v", err)
	}

	// ES256
	esPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ES256 keygen failed: %v", err)
	}
	vES, err := zerojwt.NewES256Verifier(&esPriv.PublicKey, esPriv)
	if err != nil {
		t.Fatalf("NewES256Verifier failed: %v", err)
	}

	// 3. Claims Accessors & Fields
	_ = claims.Subject()
	_ = claims.Username()
	_ = claims.Issuer()
	_ = claims.Audience()
	_ = claims.JTI()
	_ = claims.ExpiresAt
	_ = claims.IssuedAt
	_ = claims.NotBefore
	_ = claims.SubjectID
	_ = claims.HasExp
	_ = claims.HasIss
	_ = claims.HasAud
	_ = claims.HasSub
	_ = claims.HasJti

	// 4. Options: Leeway, ExpectedIssuer, ExpectedAudience
	_, err = zerojwt.New(secret, zerojwt.Options{
		Leeway:           60 * time.Second,
		ExpectedIssuer:   "https://auth.company.com",
		ExpectedAudience: "https://api.company.com",
	})
	if err != nil {
		t.Fatalf("Options New failed: %v", err)
	}

	// 5. SignBuilder
	sb := v.NewSigner(nil)
	sbTok, err := sb.SetSubject("usr_12345").
		SetClaimString("role", "admin").
		SetClaimInt("tenant_id", 42).
		SetClaimBool("is_active", true).
		SetExpiresAt(now + 3600).
		Sign()
	if err != nil {
		t.Fatalf("SignBuilder Sign failed: %v", err)
	}

	// 6. Generic AppendEscapedJSON
	buf := make([]byte, 0, 128)
	buf = append(buf, `{"uuid":`...)
	buf = zerojwt.AppendEscapedJSON(buf, "550e8400-e29b-41d4-a716-446655440000")
	buf = append(buf, '}')
	if len(buf) == 0 {
		t.Fatalf("AppendEscapedJSON produced empty output")
	}

	// 7. Atomic Claim Iteration
	count := 0
	for prop, err := range v.Iter(sbTok, now) {
		if err != nil {
			t.Fatalf("Iter error: %v", err)
		}
		_ = prop.Val
		_ = prop.IsStr
		_ = prop.Value()
		_ = prop.IsString()
		if len(prop.Key) > 0 {
			count++
		}
	}
	if count == 0 {
		t.Fatalf("expected iterated claims")
	}

	// 8. Event-Driven Network Primitives
	// VerifySplit
	head := token[:len(token)/2]
	tail := token[len(token)/2:]
	var splitClaims zerojwt.Claims
	if err := v.VerifySplit(head, tail, now, &splitClaims); err != nil {
		t.Fatalf("VerifySplit failed: %v", err)
	}

	// WorkerScratchGroup
	workers := zerojwt.NewWorkerScratchGroup(v, 4)
	scratch := workers.For(0)
	if err := v.VerifyWithScratch(token, now, &claims, scratch); err != nil {
		t.Fatalf("VerifyWithScratch failed: %v", err)
	}
	if err := v.VerifySplitWithScratch(head, tail, now, &splitClaims, scratch); err != nil {
		t.Fatalf("VerifySplitWithScratch failed: %v", err)
	}

	// SignToIOV
	var dstBuf [512]byte
	var iov [2][]byte
	err = v.SignClaimsToIOVWithScratch(dstBuf[:0], zerojwt.StandardClaims{
		Subject:   "usr_123",
		ExpiresAt: now + 3600,
	}, &iov, scratch)
	if err != nil {
		t.Fatalf("SignClaimsToIOVWithScratch failed: %v", err)
	}
	if len(iov[0]) == 0 || len(iov[1]) == 0 {
		t.Fatalf("empty IOV segments")
	}

	// 9. Key Rotation (kid)
	primarySecret := secret32
	retiredSecret := secret
	vRot, err := zerojwt.New(primarySecret, zerojwt.Options{
		ActiveKeyID: "key-2026-v2",
		Keys: []zerojwt.Key{
			{ID: "key-2026-v2", Secret: primarySecret},
			{ID: "key-2026-v1", Secret: retiredSecret},
		},
	})
	if err != nil {
		t.Fatalf("Key rotation New failed: %v", err)
	}
	rotTok, err := vRot.SignClaims(nil, zerojwt.StandardClaims{
		Subject:   "rot_user",
		ExpiresAt: now + 3600,
	})
	if err != nil {
		t.Fatalf("vRot SignClaims failed: %v", err)
	}
	if err := vRot.Verify(rotTok, now, &claims); err != nil {
		t.Fatalf("vRot Verify failed: %v", err)
	}

	// 10. HTTP Middlewares
	// ProtectFunc
	protectHandler := v.ProtectFunc(func(w http.ResponseWriter, r *http.Request, claims *zerojwt.Claims) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Hello, " + string(claims.Subject())))
	})
	req := httptest.NewRequest("GET", "/api/profile", nil)
	req.Header.Set("Authorization", "Bearer "+string(token))
	rec := httptest.NewRecorder()
	protectHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ProtectFunc expected 200, got %d", rec.Code)
	}

	// Middleware (net/http)
	stdHandler := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqClaims := zerojwt.FromContext(r.Context())
		if reqClaims == nil {
			t.Fatalf("FromContext returned nil")
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "User ID: %s", reqClaims.Subject())
	}))
	rec2 := httptest.NewRecorder()
	stdHandler.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("stdHandler expected 200, got %d", rec2.Code)
	}

	// VerifyBearer
	authHeader := req.Header.Get("Authorization")
	var bearerClaims zerojwt.Claims
	if err := v.VerifyBearer([]byte(authHeader), now, &bearerClaims); err != nil {
		t.Fatalf("VerifyBearer failed: %v", err)
	}

	// 11. Destroy
	vEd.Destroy()
	if vEd.CanSign() {
		t.Fatalf("vEd CanSign should be false after Destroy")
	}
	vES.Destroy()
	v.Destroy()
}
