package zerojwt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestStudyPrimitives(t *testing.T) {
	secret := bytes.Repeat([]byte("s"), 32)
	v, err := New(secret)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()

	// 1. Test SignToIOV and SignClaimsToIOV
	var iov [2][]byte
	var dst [512]byte

	err = v.SignToIOV(dst[:0], []byte(`{"sub":"alice","exp":1800000000}`), &iov)
	if err != nil {
		t.Fatalf("SignToIOV failed: %v", err)
	}
	if !bytes.Equal(iov[0], v.encodedHeaderDotBytes) {
		t.Fatalf("expected iov[0] to match encodedHeaderDotBytes, got %s", iov[0])
	}
	fullToken := append(append([]byte(nil), iov[0]...), iov[1]...)

	var claims Claims
	if err := v.Verify(fullToken, now, &claims); err != nil {
		t.Fatalf("failed to verify token produced by SignToIOV: %v", err)
	}
	if string(claims.Subject()) != "alice" {
		t.Fatalf("expected sub 'alice', got %s", claims.Subject())
	}

	// Test SignClaimsToIOV
	err = v.SignClaimsToIOV(dst[:0], StandardClaims{
		Subject:   "bob_iov",
		Username:  "bob",
		ExpiresAt: now + 3600,
	}, &iov)
	if err != nil {
		t.Fatalf("SignClaimsToIOV failed: %v", err)
	}
	fullToken2 := append(append([]byte(nil), iov[0]...), iov[1]...)
	if err := v.Verify(fullToken2, now, &claims); err != nil {
		t.Fatalf("failed to verify token produced by SignClaimsToIOV: %v", err)
	}
	if string(claims.Subject()) != "bob_iov" || string(claims.Username()) != "bob" {
		t.Fatalf("claims mismatch: sub=%s, user=%s", claims.Subject(), claims.Username())
	}

	// SignToIOV error branches
	vNoKey := &Verifier{maxPayloadSize: 1024}
	if err := vNoKey.SignToIOV(nil, []byte(`{"sub":"1"}`), &iov); !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("expected ErrNoSigningKey, got %v", err)
	}
	vDest := &Verifier{maxPayloadSize: 1024}
	vDest.Destroy()
	if err := vDest.SignToIOV(nil, []byte(`{"sub":"1"}`), &iov); !errors.Is(err, ErrVerifierDestroyed) {
		t.Fatalf("expected ErrVerifierDestroyed, got %v", err)
	}
	if err := v.SignToIOV(nil, bytes.Repeat([]byte("a"), 2000), &iov); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("expected ErrPayloadTooLarge, got %v", err)
	}
	if err := v.SignClaimsToIOV(nil, StandardClaims{Subject: "", ExpiresAt: now + 3600}, &iov); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for empty sub, got %v", err)
	}
	if err := v.SignClaimsToIOV(nil, StandardClaims{Subject: "alice", ExpiresAt: 0}, &iov); !errors.Is(err, ErrMissingExp) {
		t.Fatalf("expected ErrMissingExp, got %v", err)
	}

	// EdDSA and ES256 SignToIOV
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	vEd, _ := NewEd25519Verifier(edPub, edPriv)
	if err := vEd.SignToIOV(dst[:0], []byte(fmt.Sprintf(`{"sub":"ed_iov","exp":%d}`, now+1000)), &iov); err != nil {
		t.Fatalf("vEd.SignToIOV failed: %v", err)
	}
	tokEd := append(append([]byte(nil), iov[0]...), iov[1]...)
	if err := vEd.Verify(tokEd, now, &claims); err != nil {
		t.Fatalf("vEd.Verify failed: %v", err)
	}

	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	vEc, _ := NewES256Verifier(&ecPriv.PublicKey, ecPriv)
	if err := vEc.SignToIOV(dst[:0], []byte(fmt.Sprintf(`{"sub":"ec_iov","exp":%d}`, now+1000)), &iov); err != nil {
		t.Fatalf("vEc.SignToIOV failed: %v", err)
	}
	tokEc := append(append([]byte(nil), iov[0]...), iov[1]...)
	if err := vEc.Verify(tokEc, now, &claims); err != nil {
		t.Fatalf("vEc.Verify failed: %v", err)
	}

	// 2. Test VerifySplit across all split boundaries
	tokenStr, _ := v.Sign(nil, []byte(fmt.Sprintf(`{"sub":"charlie","username":"charlie_123","exp":%d}`, now+3600)))

	// Test split at EVERY byte of tokenStr
	for splitIdx := 0; splitIdx <= len(tokenStr); splitIdx++ {
		head := tokenStr[:splitIdx]
		tail := tokenStr[splitIdx:]

		var clSplit Claims
		if err := v.VerifySplit(head, tail, now, &clSplit); err != nil {
			t.Fatalf("VerifySplit failed at split index %d (len %d): %v", splitIdx, len(tokenStr), err)
		}
		if string(clSplit.Subject()) != "charlie" {
			t.Fatalf("expected 'charlie' at split index %d, got %s", splitIdx, clSplit.Subject())
		}
	}

	// VerifySplit with SignToIOV (split at exactly the first dot)
	_ = v.SignToIOV(dst[:0], []byte(fmt.Sprintf(`{"sub":"iov_split","exp":%d}`, now+3600)), &iov)
	if err := v.VerifySplit(iov[0], iov[1], now, &claims); err != nil {
		t.Fatalf("VerifySplit on IOV failed: %v", err)
	}
	if string(claims.Subject()) != "iov_split" {
		t.Fatalf("expected 'iov_split', got %s", claims.Subject())
	}

	// VerifySplit error cases
	if err := v.VerifySplit([]byte("not.a.valid"), []byte("token.extra.dot"), now, &claims); err == nil {
		t.Fatal("expected error on extra dots in tail")
	}
	if err := v.VerifySplit([]byte("no_dots_here"), []byte("no_dots_either"), now, &claims); err == nil {
		t.Fatal("expected error on missing dots")
	}
	if err := v.VerifySplit([]byte("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"), []byte(".extra"), now, &claims); err == nil {
		t.Fatal("expected error on extra dot in tail for Case 1")
	}

	// 3. Test WorkerScratchGroup
	numWorkers := 8
	group := NewWorkerScratchGroup(v, numWorkers)
	if group.Len() != numWorkers {
		t.Fatalf("expected len %d, got %d", numWorkers, group.Len())
	}

	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		workerID := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			sc := group.For(workerID)
			var cl Claims
			if err := v.VerifyWithScratch(tokenStr, now, &cl, sc); err != nil {
				t.Errorf("worker %d verify failed: %v", workerID, err)
			}
			if string(cl.Subject()) != "charlie" {
				t.Errorf("worker %d subject mismatch: %s", workerID, cl.Subject())
			}
		}()
	}
	wg.Wait()

	// Test bounds fallback
	scFallback := group.For(100)
	if scFallback == nil {
		t.Fatal("expected non-nil fallback scratch")
	}
}
