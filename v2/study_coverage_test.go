package zerojwt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestStudyFullCoverage(t *testing.T) {
	secret := bytes.Repeat([]byte("s"), 32)
	now := time.Now().Unix()

	// 1. worker.go: numWorkers <= 0
	v, err := New(secret, Options{
		ExpectedIssuer:   "auth.io",
		ExpectedAudience: "api.io",
	})
	if err != nil {
		t.Fatal(err)
	}

	g0 := NewWorkerScratchGroup(v, 0)
	if g0.Len() != 1 {
		t.Fatalf("expected len 1, got %d", g0.Len())
	}
	if g0.For(-1) == nil || g0.For(-99) == nil || g0.For(100) == nil {
		t.Fatalf("expected non-nil scratch for negative and out-of-range IDs")
	}

	// 2. iov.go error paths in SignClaimsToIOVWithScratch
	var iov [2][]byte
	vNoSign := &Verifier{maxPayloadSize: 1024}
	if err := vNoSign.SignClaimsToIOV(nil, StandardClaims{Subject: "alice", ExpiresAt: now + 3600}, &iov); !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("expected ErrNoSigningKey, got %v", err)
	}
	vDest := &Verifier{maxPayloadSize: 1024}
	vDest.Destroy()
	if err := vDest.SignClaimsToIOV(nil, StandardClaims{Subject: "alice", ExpiresAt: now + 3600}, &iov); !errors.Is(err, ErrVerifierDestroyed) {
		t.Fatalf("expected ErrVerifierDestroyed, got %v", err)
	}
	// Subject too long
	if err := v.SignClaimsToIOV(nil, StandardClaims{Subject: string(bytes.Repeat([]byte("a"), 260)), ExpiresAt: now + 3600}, &iov); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for sub > 256, got %v", err)
	}
	// Username too long
	if err := v.SignClaimsToIOV(nil, StandardClaims{Subject: "alice", Username: string(bytes.Repeat([]byte("u"), 130)), ExpiresAt: now + 3600}, &iov); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for username > 128, got %v", err)
	}
	// Issuer too long
	if err := v.SignClaimsToIOV(nil, StandardClaims{Subject: "alice", Issuer: string(bytes.Repeat([]byte("i"), 260)), ExpiresAt: now + 3600}, &iov); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for iss > 256, got %v", err)
	}
	// Audience too long
	if err := v.SignClaimsToIOV(nil, StandardClaims{Subject: "alice", Audience: string(bytes.Repeat([]byte("a"), 260)), ExpiresAt: now + 3600}, &iov); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for aud > 256, got %v", err)
	}
	// JTI too long
	if err := v.SignClaimsToIOV(nil, StandardClaims{Subject: "alice", JTI: string(bytes.Repeat([]byte("j"), 70)), ExpiresAt: now + 3600}, &iov); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for jti > 64, got %v", err)
	}

	// Full claims emission (JTI, NotBefore, IssuedAt, custom iss/aud)
	err = v.SignClaimsToIOV(nil, StandardClaims{
		Subject:   "full_claims",
		Username:  "admin",
		Issuer:    "custom.iss",
		Audience:  "custom.aud",
		JTI:       "jwt-id-99",
		IssuedAt:  now - 10,
		NotBefore: now - 5,
		ExpiresAt: now + 3600,
	}, &iov)
	if err != nil {
		t.Fatalf("full claims SignClaimsToIOV failed: %v", err)
	}

	// Default expected iss and aud emission
	err = v.SignClaimsToIOV(nil, StandardClaims{
		Subject:   "default_iss_aud",
		ExpiresAt: now + 3600,
	}, &iov)
	if err != nil {
		t.Fatalf("SignClaimsToIOV with defaults failed: %v", err)
	}

	// ES256 error with failing randReader
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	vEcErr, _ := NewES256Verifier(&ecPriv.PublicKey, ecPriv)
	vEcErr.randReader = errReader{}
	if err := vEcErr.SignToIOV(nil, []byte(fmt.Sprintf(`{"sub":"fail","exp":%d}`, now+1000)), &iov); !errors.Is(err, ErrSigningFailed) {
		t.Fatalf("expected ErrSigningFailed, got %v", err)
	}

	// EdDSA SignToIOV with payload larger than st.payloadArr
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	vEdBig, _ := NewEd25519Verifier(edPub, edPriv, Options{MaxPayloadSize: 4096})
	bigPayload := append([]byte(`{"sub":"alice","data":"`), bytes.Repeat([]byte("x"), 1500)...)
	bigPayload = append(bigPayload, []byte(fmt.Sprintf(`","exp":%d}`, now+1000))...)
	if err := vEdBig.SignToIOV(nil, bigPayload, &iov); err != nil {
		t.Fatalf("expected success for large payload in EdDSA SignToIOV, got %v", err)
	}

	// 3. split.go: decodeBase64Split errors
	var dstBuf [256]byte
	// Error in b1 full quanta
	if _, err := decodeBase64Split(dstBuf[:], []byte("!bad"), []byte("AAAA")); err == nil {
		t.Fatal("expected error for bad chars in b1")
	}
	// Error in boundary quantum
	if _, err := decodeBase64Split(dstBuf[:], []byte("AAA!"), []byte("AAAA")); err == nil {
		t.Fatal("expected error for bad boundary chars")
	}
	// Error in b2 remaining quanta
	if _, err := decodeBase64Split(dstBuf[:], []byte("AAAA"), []byte("!bad")); err == nil {
		t.Fatal("expected error for bad chars in b2")
	}
	// Short tail quantum error
	if _, err := decodeBase64Split(dstBuf[:], []byte("A"), []byte("!")); err == nil {
		t.Fatal("expected error for bad chars in short tail quantum")
	}

	// 4. split.go: verifySplitSignatureAndDecodePayload branches
	st := v.NewScratch()

	// Destroyed
	vDestroyed := &Verifier{}
	vDestroyed.Destroy()
	if _, err := vDestroyed.verifySplitSignatureAndDecodePayload([]byte("a"), []byte("b"), st); !errors.Is(err, ErrVerifierDestroyed) {
		t.Fatalf("expected ErrVerifierDestroyed, got %v", err)
	}

	// Case 2: Dot 1 in head, but no Dot 2 in tail
	if _, err := v.verifySplitSignatureAndDecodePayload([]byte("hdr."), []byte("no_second_dot"), st); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for missing dot 2, got %v", err)
	}
	// Case 2: Extra dot in signature s1
	if _, err := v.verifySplitSignatureAndDecodePayload([]byte("hdr."), []byte("pl.sig.extra"), st); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for extra dot in s1, got %v", err)
	}

	// Case 3: Dot 1 in tail, but no Dot 2 in tail
	if _, err := v.verifySplitSignatureAndDecodePayload([]byte("no_dot_here"), []byte("dot1.no_dot_2"), st); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for missing dot 2 in Case 3, got %v", err)
	}
	// Case 3: Extra dot in signature s1
	if _, err := v.verifySplitSignatureAndDecodePayload([]byte("hdr"), []byte("1.pl.sig.extra"), st); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for extra dot in s1 Case 3, got %v", err)
	}

	// Empty segment length
	if _, err := v.verifySplitSignatureAndDecodePayload([]byte("."), []byte(".s"), st); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for empty segments, got %v", err)
	}

	// Header too large
	bigHdr := bytes.Repeat([]byte("A"), 300)
	if _, err := v.verifySplitSignatureAndDecodePayload(bigHdr, []byte(".pl.sig"), st); !errors.Is(err, ErrHeaderTooLarge) {
		t.Fatalf("expected ErrHeaderTooLarge for huge header, got %v", err)
	}

	// Invalid base64 in header
	if _, err := v.verifySplitSignatureAndDecodePayload([]byte("!hdr!"), []byte(".pl.sig"), st); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for bad b64 header, got %v", err)
	}

	// Signature too large
	bigSig := bytes.Repeat([]byte("A"), 800)
	validHdr := []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.")
	if _, err := v.verifySplitSignatureAndDecodePayload(validHdr, append([]byte("eyJzdWIiOiIxIn0."), bigSig...), st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for huge signature, got %v", err)
	}

	// Invalid signature length != sigDecodedLen
	shortSig := []byte("c2ln") // 3 bytes
	if _, err := v.verifySplitSignatureAndDecodePayload(validHdr, append([]byte("eyJzdWIiOiIxIn0."), shortSig...), st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for short signature, got %v", err)
	}

	// EdDSA split verification: success and bad pub length
	vEdValid, _ := NewEd25519Verifier(edPub, edPriv)
	tokEdValid, _ := vEdValid.Sign(nil, []byte(fmt.Sprintf(`{"sub":"ed_split","exp":%d}`, now+1000)))
	var clEd Claims
	midEd := len(tokEdValid) / 2
	if err := vEdValid.VerifySplit(tokEdValid[:midEd], tokEdValid[midEd:], now, &clEd); err != nil {
		t.Fatalf("VerifySplit on EdDSA failed: %v", err)
	}

	// EdDSA with large payload requiring heap allocation in signInput
	bigEdTok, _ := vEdBig.Sign(nil, bigPayload)
	midBigEd := len(bigEdTok) / 2
	if err := vEdBig.VerifySplit(bigEdTok[:midBigEd], bigEdTok[midBigEd:], now, &clEd); err != nil {
		t.Fatalf("VerifySplit on large EdDSA token failed: %v", err)
	}

	// EdDSA bad pub length
	vEdBadPub := &Verifier{
		alg:           AlgEdDSA,
		algBytes:      []byte(AlgEdDSA),
		sigDecodedLen: 64,
		keys: []compiledKey{
			{idBytes: []byte("k1"), ed25519Public: make([]byte, 10)},
		},
	}
	hdrEdKid := []byte("eyJhbGciOiJFZERTQSIgLCJraWQiOiJrMSJ9.")
	dummySig64 := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if _, err := vEdBadPub.verifySplitSignatureAndDecodePayload(hdrEdKid, append([]byte("eyJzdWIiOiIxIn0."), dummySig64...), st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature on bad EdDSA pub, got %v", err)
	}

	// ES256 split verification: success and nil pub
	vEcValid, _ := NewES256Verifier(&ecPriv.PublicKey, ecPriv)
	tokEcValid, _ := vEcValid.Sign(nil, []byte(fmt.Sprintf(`{"sub":"ec_split","exp":%d}`, now+1000)))
	var clEc Claims
	midEc := len(tokEcValid) / 2
	if err := vEcValid.VerifySplit(tokEcValid[:midEc], tokEcValid[midEc:], now, &clEc); err != nil {
		t.Fatalf("VerifySplit on ES256 failed: %v", err)
	}

	vEcNilPub := &Verifier{
		alg:           AlgES256,
		algBytes:      []byte(AlgES256),
		sigDecodedLen: 64,
		keys: []compiledKey{
			{idBytes: []byte("k1"), ecdsaPublic: nil},
		},
	}
	hdrEcKid := []byte("eyJhbGciOiJFUzI1NiIsImtpZCI6ImsxIn0.")
	if _, err := vEcNilPub.verifySplitSignatureAndDecodePayload(hdrEcKid, append([]byte("eyJzdWIiOiIxIn0."), dummySig64...), st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature on nil ES256 pub, got %v", err)
	}

	// ES256 signature verification failure
	if _, err := vEcValid.verifySplitSignatureAndDecodePayload(tokEcValid[:10], append([]byte(tokEcValid[10:len(tokEcValid)-4]), []byte("AAAA")...), st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature on bad ES256 signature, got %v", err)
	}

	// Rotated key empty secret in HS256
	vHSEmptySec := &Verifier{
		alg:           AlgHS256,
		algBytes:      []byte(AlgHS256),
		sigDecodedLen: 32,
		keys: []compiledKey{
			{idBytes: []byte("k1"), secret: nil},
		},
	}
	hdrHSKid := []byte("eyJhbGciOiJIUzI1NiIsImtpZCI6ImsxIn0.")
	dummySig32 := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if _, err := vHSEmptySec.verifySplitSignatureAndDecodePayload(hdrHSKid, append([]byte("eyJzdWIiOiIxIn0."), dummySig32...), st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for empty rotated secret, got %v", err)
	}

	// Verifier with empty default secret in split
	vEmptySec := &Verifier{
		alg:           AlgHS256,
		algBytes:      []byte(AlgHS256),
		sigDecodedLen: 32,
	}
	if _, err := vEmptySec.verifySplitSignatureAndDecodePayload(validHdr, append([]byte("eyJzdWIiOiIxIn0."), dummySig32...), st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for empty secret, got %v", err)
	}

	// Payload too large
	vSmall, _ := New(secret, Options{MaxPayloadSize: 64})
	stSmall := vSmall.acquireScratch()
	tokLarge, _ := v.Sign(nil, []byte(fmt.Sprintf(`{"sub":"alice","data":"%s","exp":%d}`, bytes.Repeat([]byte("d"), 100), now+1000)))
	if _, err := vSmall.verifySplitSignatureAndDecodePayload(tokLarge[:10], tokLarge[10:], stSmall); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("expected ErrPayloadTooLarge for huge payload in split, got %v", err)
	}

	// Invalid base64 in payload with valid signature
	badB64Input := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.!!!not-base64!!!"
	macBadB64 := hmac.New(sha256.New, secret)
	macBadB64.Write([]byte(badB64Input))
	sigBadB64 := base64.RawURLEncoding.EncodeToString(macBadB64.Sum(nil))
	tokBadB64 := []byte(badB64Input + "." + sigBadB64)
	if _, err := v.verifySplitSignatureAndDecodePayload(tokBadB64[:10], tokBadB64[10:], st); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for bad b64 in payload, got %v", err)
	}

	// decodeBase64Split error in boundary quantum
	if _, err := decodeBase64Split(dstBuf[:], []byte("A"), []byte("!AA")); err == nil {
		t.Fatal("expected error for bad chars in boundary quantum")
	}

	// validateHeader error in split
	badAlgHdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	if _, err := v.verifySplitSignatureAndDecodePayload([]byte(badAlgHdr[:10]), []byte(badAlgHdr[10:]+".eyJzdWIiOiIxIn0."+string(dummySig32)), st); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for split header, got %v", err)
	}

	// EdDSA signature verification failure in split
	dummy64B := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 64))
	hdrEd := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`))
	tokEdBad := []byte(hdrEd + ".eyJzdWIiOiIxIn0." + dummy64B)
	if _, err := vEdValid.verifySplitSignatureAndDecodePayload(tokEdBad[:10], tokEdBad[10:], st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature on failed EdDSA verify in split, got %v", err)
	}

	// ES256 derSig encode failure in split (all zeros IEEE P1363)
	dummyZeros64 := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	hdrEc := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	tokEcZeros := []byte(hdrEc + ".eyJzdWIiOiIxIn0." + dummyZeros64)
	if _, err := vEcValid.verifySplitSignatureAndDecodePayload(tokEcZeros[:10], tokEcZeros[10:], st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature on DER encode failure, got %v", err)
	}

	// HMAC mismatch in split
	if _, err := v.verifySplitSignatureAndDecodePayload(validHdr, append([]byte("eyJzdWIiOiIxIn0."), dummySig32...), st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature on HMAC mismatch in split, got %v", err)
	}

	// Rotated key with valid secret in split
	vHSRotValid, _ := New(secret, Options{
		Keys: []Key{
			{ID: "k1", Secret: bytes.Repeat([]byte("2"), 32)},
		},
	})
	stRot := vHSRotValid.acquireScratch()
	hdrRotKid := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":"k1"}`))
	tokRotBad := []byte(hdrRotKid + ".eyJzdWIiOiIxIn0." + string(dummySig32))
	if _, err := vHSRotValid.verifySplitSignatureAndDecodePayload([]byte(tokRotBad[:10]), []byte(tokRotBad[10:]), stRot); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature on rotated key in split, got %v", err)
	}
}
