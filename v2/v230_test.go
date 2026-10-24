package zerojwt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"
)

func TestV230_SignAndVerify_RS256(t *testing.T) {
	// Generate RSA 2048 key
	rsaPriv2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaPub2048 := &rsaPriv2048.PublicKey

	// Verifier with priv key
	v2048, err := NewRS256Verifier(rsaPub2048, rsaPriv2048)
	if err != nil {
		t.Fatalf("NewRS256Verifier failed: %v", err)
	}
	if !v2048.CanSign() {
		t.Fatal("expected CanSign true")
	}
	if v2048.Algorithm() != AlgRS256 {
		t.Fatalf("expected AlgRS256, got %v", v2048.Algorithm())
	}

	// Verification-only verifier
	vVerifyOnly, err := NewRS256Verifier(rsaPub2048, nil)
	if err != nil {
		t.Fatalf("NewRS256Verifier verify-only failed: %v", err)
	}
	if vVerifyOnly.CanSign() {
		t.Fatal("expected CanSign false for verify-only")
	}

	// Sign payload
	now := time.Now().Unix()
	pl := []byte(fmt.Sprintf(`{"sub":"alice","exp":%d}`, now+3600))
	tok, err := v2048.Sign(nil, pl)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify with both
	var cl Claims
	if err := v2048.Verify(tok, now, &cl); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if string(cl.Subject()) != "alice" {
		t.Fatalf("expected alice, got %s", string(cl.Subject()))
	}
	if err := vVerifyOnly.Verify(tok, now, &cl); err != nil {
		t.Fatalf("Verify with verify-only failed: %v", err)
	}

	// VerifyBearer
	authHeader := append([]byte("Bearer "), tok...)
	if err := v2048.VerifyBearer(authHeader, now, &cl); err != nil {
		t.Fatalf("VerifyBearer failed: %v", err)
	}

	// VerifyAndIterate
	sawSub := false
	err = v2048.VerifyAndIterate(tok, now, func(key, val []byte, isStr bool) bool {
		if string(key) == "sub" && string(val) == "alice" {
			sawSub = true
		}
		return true
	})
	if err != nil || !sawSub {
		t.Fatalf("VerifyAndIterate failed: err=%v, sawSub=%v", err, sawSub)
	}

	// VerifySplit: Case 1 (both dots in head)
	dot1 := bytes.IndexByte(tok, '.')
	dot2 := bytes.LastIndexByte(tok, '.')
	splitIdx1 := dot2 + 5
	if err := v2048.VerifySplit(tok[:splitIdx1], tok[splitIdx1:], now, &cl); err != nil {
		t.Fatalf("VerifySplit Case 1 failed: %v", err)
	}

	// VerifySplit: Case 2 (dot 1 in head, dot 2 in tail)
	splitIdx2 := (dot1 + dot2) / 2
	if err := v2048.VerifySplit(tok[:splitIdx2], tok[splitIdx2:], now, &cl); err != nil {
		t.Fatalf("VerifySplit Case 2 failed: %v", err)
	}

	// VerifySplit: Case 3 (dot 1 in tail)
	splitIdx3 := dot1 - 2
	if err := v2048.VerifySplit(tok[:splitIdx3], tok[splitIdx3:], now, &cl); err != nil {
		t.Fatalf("VerifySplit Case 3 failed: %v", err)
	}

	// VerifySplitAndIterate
	sawSubSplit := false
	err = v2048.VerifySplitAndIterate(tok[:splitIdx2], tok[splitIdx2:], now, func(key, val []byte, isStr bool) bool {
		if string(key) == "sub" {
			sawSubSplit = true
		}
		return true
	})
	if err != nil || !sawSubSplit {
		t.Fatalf("VerifySplitAndIterate failed: err=%v", err)
	}

	// Corrupted signature
	badTok := append([]byte(nil), tok...)
	badTok[len(badTok)-5] ^= 0x01
	if err := v2048.Verify(badTok, now, &cl); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
	if err := v2048.VerifySplit(badTok[:splitIdx2], badTok[splitIdx2:], now, &cl); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature in split, got %v", err)
	}

	// SignClaims
	claimsTok, err := v2048.SignClaims(nil, StandardClaims{
		Subject:   "bob",
		ExpiresAt: now + 3600,
	})
	if err != nil {
		t.Fatalf("SignClaims failed: %v", err)
	}
	if err := v2048.Verify(claimsTok, now, &cl); err != nil || string(cl.Subject()) != "bob" {
		t.Fatalf("Verify of SignClaims failed: %v", err)
	}

	// SignToIOV & SignClaimsToIOV
	var iov [2][]byte
	var iovDst [1024]byte
	if err := v2048.SignToIOV(iovDst[:0], pl, &iov); err != nil {
		t.Fatalf("SignToIOV failed: %v", err)
	}
	combinedTok := append(append([]byte(nil), iov[0]...), iov[1]...)
	if err := v2048.Verify(combinedTok, now, &cl); err != nil {
		t.Fatalf("Verify of SignToIOV token failed: %v", err)
	}

	if err := v2048.SignClaimsToIOV(iovDst[:0], StandardClaims{
		Subject:   "charlie",
		ExpiresAt: now + 3600,
	}, &iov); err != nil {
		t.Fatalf("SignClaimsToIOV failed: %v", err)
	}
	combinedTokClaims := append(append([]byte(nil), iov[0]...), iov[1]...)
	if err := v2048.Verify(combinedTokClaims, now, &cl); err != nil || string(cl.Subject()) != "charlie" {
		t.Fatalf("Verify of SignClaimsToIOV token failed: %v", err)
	}

	// RSA 4096-bit key test (demonstrating dynamic key-size support)
	rsaPriv4096, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	v4096, err := NewRS256Verifier(&rsaPriv4096.PublicKey, rsaPriv4096)
	if err != nil {
		t.Fatalf("NewRS256Verifier 4096 failed: %v", err)
	}
	tok4096, err := v4096.Sign(nil, pl)
	if err != nil {
		t.Fatalf("Sign 4096 failed: %v", err)
	}
	if err := v4096.Verify(tok4096, now, &cl); err != nil {
		t.Fatalf("Verify 4096 failed: %v", err)
	}
	// SignToIOV with 4096-bit key
	var iov4096 [2][]byte
	var iovDst4096 [2048]byte
	if err := v4096.SignToIOV(iovDst4096[:0], pl, &iov4096); err != nil {
		t.Fatalf("SignToIOV 4096 failed: %v", err)
	}
	comb4096 := append(append([]byte(nil), iov4096[0]...), iov4096[1]...)
	if err := v4096.Verify(comb4096, now, &cl); err != nil {
		t.Fatalf("Verify 4096 IOV failed: %v", err)
	}
}

func TestV230_SignAndVerify_ES384(t *testing.T) {
	priv384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub384 := &priv384.PublicKey

	v, err := NewES384Verifier(pub384, priv384)
	if err != nil {
		t.Fatalf("NewES384Verifier failed: %v", err)
	}
	if !v.CanSign() {
		t.Fatal("expected CanSign true")
	}
	if v.Algorithm() != AlgES384 {
		t.Fatalf("expected AlgES384, got %v", v.Algorithm())
	}

	vVerifyOnly, err := NewES384Verifier(pub384, nil)
	if err != nil {
		t.Fatalf("NewES384Verifier verify-only failed: %v", err)
	}

	now := time.Now().Unix()
	pl := []byte(fmt.Sprintf(`{"sub":"alice_es384","exp":%d}`, now+3600))
	tok, err := v.Sign(nil, pl)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	var cl Claims
	if err := v.Verify(tok, now, &cl); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if string(cl.Subject()) != "alice_es384" {
		t.Fatalf("expected alice_es384, got %s", string(cl.Subject()))
	}
	if err := vVerifyOnly.Verify(tok, now, &cl); err != nil {
		t.Fatalf("Verify with verify-only failed: %v", err)
	}

	// VerifyBearer
	authHeader := append([]byte("Bearer "), tok...)
	if err := v.VerifyBearer(authHeader, now, &cl); err != nil {
		t.Fatalf("VerifyBearer failed: %v", err)
	}

	// VerifyAndIterate
	sawSub := false
	err = v.VerifyAndIterate(tok, now, func(key, val []byte, isStr bool) bool {
		if string(key) == "sub" {
			sawSub = true
		}
		return true
	})
	if err != nil || !sawSub {
		t.Fatalf("VerifyAndIterate failed: err=%v", err)
	}

	// VerifySplit
	dot1 := bytes.IndexByte(tok, '.')
	dot2 := bytes.LastIndexByte(tok, '.')
	splitIdx := (dot1 + dot2) / 2
	if err := v.VerifySplit(tok[:splitIdx], tok[splitIdx:], now, &cl); err != nil {
		t.Fatalf("VerifySplit failed: %v", err)
	}

	// VerifySplitAndIterate
	sawSplit := false
	err = v.VerifySplitAndIterate(tok[:splitIdx], tok[splitIdx:], now, func(key, val []byte, isStr bool) bool {
		if string(key) == "sub" {
			sawSplit = true
		}
		return true
	})
	if err != nil || !sawSplit {
		t.Fatalf("VerifySplitAndIterate failed: err=%v", err)
	}

	// Corrupted signature
	badTok := append([]byte(nil), tok...)
	badTok[len(badTok)-5] ^= 0x01
	if err := v.Verify(badTok, now, &cl); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
	if err := v.VerifySplit(badTok[:splitIdx], badTok[splitIdx:], now, &cl); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature in split, got %v", err)
	}

	// SignToIOV
	var iov [2][]byte
	var iovDst [512]byte
	if err := v.SignToIOV(iovDst[:0], pl, &iov); err != nil {
		t.Fatalf("SignToIOV failed: %v", err)
	}
	comb := append(append([]byte(nil), iov[0]...), iov[1]...)
	if err := v.Verify(comb, now, &cl); err != nil {
		t.Fatalf("Verify IOV failed: %v", err)
	}

	// SignClaimsToIOV
	if err := v.SignClaimsToIOV(iovDst[:0], StandardClaims{
		Subject:   "dana",
		ExpiresAt: now + 3600,
	}, &iov); err != nil {
		t.Fatalf("SignClaimsToIOV failed: %v", err)
	}
	combClaims := append(append([]byte(nil), iov[0]...), iov[1]...)
	if err := v.Verify(combClaims, now, &cl); err != nil || string(cl.Subject()) != "dana" {
		t.Fatalf("Verify SignClaimsToIOV failed: %v", err)
	}
}

func TestV230_SignAndVerify_ES512(t *testing.T) {
	priv521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub521 := &priv521.PublicKey

	v, err := NewES512Verifier(pub521, priv521)
	if err != nil {
		t.Fatalf("NewES512Verifier failed: %v", err)
	}
	if !v.CanSign() {
		t.Fatal("expected CanSign true")
	}
	if v.Algorithm() != AlgES512 {
		t.Fatalf("expected AlgES512, got %v", v.Algorithm())
	}

	vVerifyOnly, err := NewES512Verifier(pub521, nil)
	if err != nil {
		t.Fatalf("NewES512Verifier verify-only failed: %v", err)
	}

	now := time.Now().Unix()
	pl := []byte(fmt.Sprintf(`{"sub":"alice_es512","exp":%d}`, now+3600))
	tok, err := v.Sign(nil, pl)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	var cl Claims
	if err := v.Verify(tok, now, &cl); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if string(cl.Subject()) != "alice_es512" {
		t.Fatalf("expected alice_es512, got %s", string(cl.Subject()))
	}
	if err := vVerifyOnly.Verify(tok, now, &cl); err != nil {
		t.Fatalf("Verify with verify-only failed: %v", err)
	}

	// VerifyBearer
	authHeader := append([]byte("Bearer "), tok...)
	if err := v.VerifyBearer(authHeader, now, &cl); err != nil {
		t.Fatalf("VerifyBearer failed: %v", err)
	}

	// VerifyAndIterate
	sawSub := false
	err = v.VerifyAndIterate(tok, now, func(key, val []byte, isStr bool) bool {
		if string(key) == "sub" {
			sawSub = true
		}
		return true
	})
	if err != nil || !sawSub {
		t.Fatalf("VerifyAndIterate failed: err=%v", err)
	}

	// VerifySplit
	dot1 := bytes.IndexByte(tok, '.')
	dot2 := bytes.LastIndexByte(tok, '.')
	splitIdx := (dot1 + dot2) / 2
	if err := v.VerifySplit(tok[:splitIdx], tok[splitIdx:], now, &cl); err != nil {
		t.Fatalf("VerifySplit failed: %v", err)
	}

	// VerifySplitAndIterate
	sawSplit := false
	err = v.VerifySplitAndIterate(tok[:splitIdx], tok[splitIdx:], now, func(key, val []byte, isStr bool) bool {
		if string(key) == "sub" {
			sawSplit = true
		}
		return true
	})
	if err != nil || !sawSplit {
		t.Fatalf("VerifySplitAndIterate failed: err=%v", err)
	}

	// Corrupted signature
	badTok := append([]byte(nil), tok...)
	badTok[len(badTok)-5] ^= 0x01
	if err := v.Verify(badTok, now, &cl); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
	if err := v.VerifySplit(badTok[:splitIdx], badTok[splitIdx:], now, &cl); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature in split, got %v", err)
	}

	// Validly formatted Base64 signature that fails ecdsa.VerifyASN1
	rawSig := make([]byte, 132)
	for i := range rawSig {
		rawSig[i] = 0x55
	}
	badSigB64 := base64.RawURLEncoding.EncodeToString(rawSig)
	badSigTok := append(append([]byte(nil), tok[:dot2+1]...), badSigB64...)
	if err := v.Verify(badSigTok, now, &cl); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for invalid ES512 sig, got %v", err)
	}
	if err := v.VerifySplit(badSigTok[:splitIdx], badSigTok[splitIdx:], now, &cl); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for invalid ES512 sig split, got %v", err)
	}

	// SignToIOV
	var iov [2][]byte
	var iovDst [512]byte
	if err := v.SignToIOV(iovDst[:0], pl, &iov); err != nil {
		t.Fatalf("SignToIOV failed: %v", err)
	}
	comb := append(append([]byte(nil), iov[0]...), iov[1]...)
	if err := v.Verify(comb, now, &cl); err != nil {
		t.Fatalf("Verify IOV failed: %v", err)
	}

	// SignClaimsToIOV
	if err := v.SignClaimsToIOV(iovDst[:0], StandardClaims{
		Subject:   "eve",
		ExpiresAt: now + 3600,
	}, &iov); err != nil {
		t.Fatalf("SignClaimsToIOV failed: %v", err)
	}
	combClaims := append(append([]byte(nil), iov[0]...), iov[1]...)
	if err := v.Verify(combClaims, now, &cl); err != nil || string(cl.Subject()) != "eve" {
		t.Fatalf("Verify SignClaimsToIOV failed: %v", err)
	}
}

func TestV230_KeyRotationAndKid(t *testing.T) {
	// 1. RSA Rotation with 2048-bit and 4096-bit keys in same keySet
	rsaPriv1, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaPriv2, _ := rsa.GenerateKey(rand.Reader, 4096)

	vRSA, err := New(nil, Options{
		Algorithm: AlgRS256,
		Keys: []Key{
			{ID: "rsa-2048", RSAPublic: &rsaPriv1.PublicKey},
			{ID: "rsa-4096", RSAPublic: &rsaPriv2.PublicKey},
		},
	})
	if err != nil {
		t.Fatalf("New RS256 with Keys failed: %v", err)
	}

	now := time.Now().Unix()
	pl := []byte(fmt.Sprintf(`{"sub":"rot_user","exp":%d}`, now+3600))

	// Issue token with key 1
	signer1, _ := NewRS256Verifier(&rsaPriv1.PublicKey, rsaPriv1, Options{ActiveKeyID: "rsa-2048"})
	tok1, err := signer1.Sign(nil, pl)
	if err != nil {
		t.Fatalf("Sign key 1 failed: %v", err)
	}
	var cl Claims
	if err := vRSA.Verify(tok1, now, &cl); err != nil {
		t.Fatalf("Verify key 1 failed: %v", err)
	}

	// Issue token with key 2 (4096-bit)
	signer2, _ := NewRS256Verifier(&rsaPriv2.PublicKey, rsaPriv2, Options{ActiveKeyID: "rsa-4096"})
	tok2, err := signer2.Sign(nil, pl)
	if err != nil {
		t.Fatalf("Sign key 2 failed: %v", err)
	}
	if err := vRSA.Verify(tok2, now, &cl); err != nil {
		t.Fatalf("Verify key 2 failed: %v", err)
	}

	// VerifySplit with key 2 (tests split.go RS256 with kid and 4096-bit signature)
	dot1 := bytes.IndexByte(tok2, '.')
	dot2 := bytes.LastIndexByte(tok2, '.')
	splitIdx := (dot1 + dot2) / 2
	if err := vRSA.VerifySplit(tok2[:splitIdx], tok2[splitIdx:], now, &cl); err != nil {
		t.Fatalf("VerifySplit key 2 failed: %v", err)
	}

	// UpdateKeys with a 3rd key
	rsaPriv3, _ := rsa.GenerateKey(rand.Reader, 2048)
	err = vRSA.UpdateKeys([]Key{
		{ID: "rsa-new", RSAPublic: &rsaPriv3.PublicKey},
	})
	if err != nil {
		t.Fatalf("UpdateKeys failed: %v", err)
	}
	// Old keys now unknown
	if err := vRSA.Verify(tok1, now, &cl); !errors.Is(err, ErrUnknownKeyID) {
		t.Fatalf("expected ErrUnknownKeyID, got %v", err)
	}

	// 2. ES384 Key rotation
	es384Priv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	vES384, err := New(nil, Options{
		Algorithm: AlgES384,
		Keys: []Key{
			{ID: "es384-k1", ECDSAPublic: &es384Priv.PublicKey},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	signerES384, _ := NewES384Verifier(&es384Priv.PublicKey, es384Priv, Options{ActiveKeyID: "es384-k1"})
	tokES384, err := signerES384.Sign(nil, pl)
	if err != nil {
		t.Fatal(err)
	}
	if err := vES384.Verify(tokES384, now, &cl); err != nil {
		t.Fatalf("Verify ES384 rotated failed: %v", err)
	}
	if err := vES384.VerifySplit(tokES384[:splitIdx], tokES384[splitIdx:], now, &cl); err != nil {
		t.Fatalf("VerifySplit ES384 rotated failed: %v", err)
	}

	// 3. ES512 Key rotation
	es512Priv, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	vES512, err := New(nil, Options{
		Algorithm: AlgES512,
		Keys: []Key{
			{ID: "es512-k1", ECDSAPublic: &es512Priv.PublicKey},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	signerES512, _ := NewES512Verifier(&es512Priv.PublicKey, es512Priv, Options{ActiveKeyID: "es512-k1"})
	tokES512, err := signerES512.Sign(nil, pl)
	if err != nil {
		t.Fatal(err)
	}
	if err := vES512.Verify(tokES512, now, &cl); err != nil {
		t.Fatalf("Verify ES512 rotated failed: %v", err)
	}
	if err := vES512.VerifySplit(tokES512[:splitIdx], tokES512[splitIdx:], now, &cl); err != nil {
		t.Fatalf("VerifySplit ES512 rotated failed: %v", err)
	}
}

func TestV230_ConfigValidation(t *testing.T) {
	// RS256 missing key
	if _, err := New(nil, Options{Algorithm: AlgRS256}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for missing RSA key, got %v", err)
	}

	// RS256 invalid public key (short modulus 1024 bits)
	shortRSA, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := NewRS256Verifier(&shortRSA.PublicKey, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for 1024-bit RSA key, got %v", err)
	}

	// RS256 with nil N
	if _, err := NewRS256Verifier(&rsa.PublicKey{E: 65537}, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for nil N, got %v", err)
	}

	// RS256 with even N
	evenN := new(big.Int).Lsh(big.NewInt(1), 2048) // power of 2, even
	if _, err := NewRS256Verifier(&rsa.PublicKey{N: evenN, E: 65537}, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for even N, got %v", err)
	}

	// RS256 with invalid E (< 65537)
	validPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := NewRS256Verifier(&rsa.PublicKey{N: validPriv.N, E: 3}, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for E=3, got %v", err)
	}
	// RS256 with even E
	if _, err := NewRS256Verifier(&rsa.PublicKey{N: validPriv.N, E: 65538}, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for even E, got %v", err)
	}

	// RS256 mismatched keypair
	otherPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := NewRS256Verifier(&validPriv.PublicKey, otherPriv); !errors.Is(err, ErrMismatchedKeyPair) {
		t.Fatalf("expected ErrMismatchedKeyPair, got %v", err)
	}

	// RS256 invalid private key (e.g. priv.Validate() failure)
	corruptPriv := *validPriv
	corruptPriv.D = big.NewInt(1)
	if _, err := NewRS256Verifier(nil, &corruptPriv); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for corrupt private key, got %v", err)
	}

	// RS256 with private key only (auto-derives public key)
	vPrivOnly, err := NewRS256Verifier(nil, validPriv)
	if err != nil || vPrivOnly.rsaPub == nil {
		t.Fatalf("expected success and derived pub key, err=%v", err)
	}

	// RS256 invalid key in Keys list
	if _, err := New(nil, Options{
		Algorithm: AlgRS256,
		Keys:      []Key{{ID: "bad", RSAPublic: &rsa.PublicKey{E: 3}}},
	}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for bad key in Keys, got %v", err)
	}

	// ES384 missing key
	if _, err := New(nil, Options{Algorithm: AlgES384}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for missing ES384 key, got %v", err)
	}
	// ES384 wrong curve (P-256 given)
	p256Key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := NewES384Verifier(&p256Key.PublicKey, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for P-256 key in ES384, got %v", err)
	}
	// ES384 invalid private scalar D
	p384Key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	badD384 := *p384Key
	badD384.D = big.NewInt(0)
	if _, err := NewES384Verifier(nil, &badD384); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for D=0 in ES384, got %v", err)
	}
	// ES384 mismatched keypair
	otherP384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := NewES384Verifier(&p384Key.PublicKey, otherP384); !errors.Is(err, ErrMismatchedKeyPair) {
		t.Fatalf("expected ErrMismatchedKeyPair in ES384, got %v", err)
	}
	// ES384 invalid in Keys
	if _, err := New(nil, Options{
		Algorithm: AlgES384,
		Keys:      []Key{{ID: "bad", ECDSAPublic: &p256Key.PublicKey}},
	}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for P-256 in ES384 Keys, got %v", err)
	}

	// ES512 missing key
	if _, err := New(nil, Options{Algorithm: AlgES512}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for missing ES512 key, got %v", err)
	}
	// ES512 wrong curve (P-384 given)
	if _, err := NewES512Verifier(&p384Key.PublicKey, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for P-384 key in ES512, got %v", err)
	}
	// ES512 invalid private scalar D
	p521Key, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	badD521 := *p521Key
	badD521.D = big.NewInt(0)
	if _, err := NewES512Verifier(nil, &badD521); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for D=0 in ES512, got %v", err)
	}
	// ES512 mismatched keypair
	otherP521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if _, err := NewES512Verifier(&p521Key.PublicKey, otherP521); !errors.Is(err, ErrMismatchedKeyPair) {
		t.Fatalf("expected ErrMismatchedKeyPair in ES512, got %v", err)
	}
	// ES512 invalid in Keys
	if _, err := New(nil, Options{
		Algorithm: AlgES512,
		Keys:      []Key{{ID: "bad", ECDSAPublic: &p384Key.PublicKey}},
	}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for P-384 in ES512 Keys, got %v", err)
	}
}

func TestV230_JWKS_RSA(t *testing.T) {
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	nB64 := base64.RawURLEncoding.EncodeToString(rsaPriv.N.Bytes())
	eB64 := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaPriv.E)).Bytes())

	// Valid RSA JWKS
	validJWKS := []byte(fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"rsa-k1","use":"sig","alg":"RS256","n":%q,"e":%q}]}`, nB64, eB64))
	keys, err := ParseJWKS(validJWKS)
	if err != nil {
		t.Fatalf("ParseJWKS valid RSA failed: %v", err)
	}
	if len(keys) != 1 || keys[0].RSAPublic == nil || keys[0].RSAPublic.N.Cmp(rsaPriv.N) != 0 {
		t.Fatalf("unexpected parsed RSA key: %+v", keys)
	}

	// UpdateKeysFromJWKS
	v, _ := New(nil, Options{
		Algorithm: AlgRS256,
		Keys:      []Key{{ID: "init", RSAPublic: &rsaPriv.PublicKey}},
	})
	if err := v.UpdateKeysFromJWKS(validJWKS); err != nil {
		t.Fatalf("UpdateKeysFromJWKS RSA failed: %v", err)
	}

	// Adversarial 1: Leading zero in n (RFC 7518 §6.3.1.1)
	nWithZero := append([]byte{0x00}, rsaPriv.N.Bytes()...)
	nWithZeroB64 := base64.RawURLEncoding.EncodeToString(nWithZero)
	badNZero := []byte(fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"bad-n","n":%q,"e":%q}]}`, nWithZeroB64, eB64))
	if _, err := ParseJWKS(badNZero); !errors.Is(err, ErrInvalidJWKS) {
		t.Fatalf("expected ErrInvalidJWKS for leading zero in n, got %v", err)
	}

	// Adversarial 2: Leading zero in e (RFC 7518 §6.3.1.1)
	eWithZero := append([]byte{0x00}, big.NewInt(int64(rsaPriv.E)).Bytes()...)
	eWithZeroB64 := base64.RawURLEncoding.EncodeToString(eWithZero)
	badEZero := []byte(fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"bad-e","n":%q,"e":%q}]}`, nB64, eWithZeroB64))
	if _, err := ParseJWKS(badEZero); !errors.Is(err, ErrInvalidJWKS) {
		t.Fatalf("expected ErrInvalidJWKS for leading zero in e, got %v", err)
	}

	// Adversarial 3: Modulus < 2048 bits
	shortPriv, _ := rsa.GenerateKey(rand.Reader, 1024)
	shortNB64 := base64.RawURLEncoding.EncodeToString(shortPriv.N.Bytes())
	badShortMod := []byte(fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"short","n":%q,"e":%q}]}`, shortNB64, eB64))
	if _, err := ParseJWKS(badShortMod); !errors.Is(err, ErrInvalidJWKS) {
		t.Fatalf("expected ErrInvalidJWKS for short modulus, got %v", err)
	}

	// Adversarial 4: Even modulus
	evenN := new(big.Int).Lsh(big.NewInt(1), 2048)
	evenNB64 := base64.RawURLEncoding.EncodeToString(evenN.Bytes())
	badEvenMod := []byte(fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"even","n":%q,"e":%q}]}`, evenNB64, eB64))
	if _, err := ParseJWKS(badEvenMod); !errors.Is(err, ErrInvalidJWKS) {
		t.Fatalf("expected ErrInvalidJWKS for even modulus, got %v", err)
	}

	// Adversarial 5: Small exponent (E=3)
	e3B64 := base64.RawURLEncoding.EncodeToString([]byte{3})
	badE3 := []byte(fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"e3","n":%q,"e":%q}]}`, nB64, e3B64))
	if _, err := ParseJWKS(badE3); !errors.Is(err, ErrInvalidJWKS) {
		t.Fatalf("expected ErrInvalidJWKS for E=3, got %v", err)
	}

	// Adversarial 6: Even exponent
	evenEB64 := base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x00, 0x02}) // 65538
	badEvenE := []byte(fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"even-e","n":%q,"e":%q}]}`, nB64, evenEB64))
	if _, err := ParseJWKS(badEvenE); !errors.Is(err, ErrInvalidJWKS) {
		t.Fatalf("expected ErrInvalidJWKS for even E, got %v", err)
	}

	// Adversarial 7: Inconsistent algorithm (alg: "ES256" on RSA key)
	badAlg := []byte(fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"bad-alg","alg":"ES256","n":%q,"e":%q}]}`, nB64, eB64))
	if _, err := ParseJWKS(badAlg); !errors.Is(err, ErrInvalidJWKS) {
		t.Fatalf("expected ErrInvalidJWKS for inconsistent alg, got %v", err)
	}

	// Adversarial 8: Missing n or e
	missingN := []byte(fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"m-n","e":%q}]}`, eB64))
	if _, err := ParseJWKS(missingN); !errors.Is(err, ErrInvalidJWKS) {
		t.Fatalf("expected ErrInvalidJWKS for missing n, got %v", err)
	}
	missingE := []byte(fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"m-e","n":%q}]}`, nB64))
	if _, err := ParseJWKS(missingE); !errors.Is(err, ErrInvalidJWKS) {
		t.Fatalf("expected ErrInvalidJWKS for missing e, got %v", err)
	}
}

func TestV230_JWKS_EC_P384_P521(t *testing.T) {
	// 1. Valid P-384
	p384Priv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	x384 := p384Priv.X.FillBytes(make([]byte, 48))
	y384 := p384Priv.Y.FillBytes(make([]byte, 48))
	x384B64 := base64.RawURLEncoding.EncodeToString(x384)
	y384B64 := base64.RawURLEncoding.EncodeToString(y384)

	jwksP384 := []byte(fmt.Sprintf(`{"keys":[{"kty":"EC","kid":"p384-k1","crv":"P-384","alg":"ES384","x":%q,"y":%q}]}`, x384B64, y384B64))
	keys384, err := ParseJWKS(jwksP384)
	if err != nil {
		t.Fatalf("ParseJWKS P-384 failed: %v", err)
	}
	if len(keys384) != 1 || keys384[0].ECDSAPublic == nil || keys384[0].ECDSAPublic.Curve != elliptic.P384() {
		t.Fatalf("unexpected parsed P-384 key: %+v", keys384)
	}

	// UpdateKeysFromJWKS P-384
	v384, _ := New(nil, Options{
		Algorithm: AlgES384,
		Keys:      []Key{{ID: "init", ECDSAPublic: &p384Priv.PublicKey}},
	})
	if err := v384.UpdateKeysFromJWKS(jwksP384); err != nil {
		t.Fatalf("UpdateKeysFromJWKS P-384 failed: %v", err)
	}

	// 2. Valid P-521
	p521Priv, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	x521 := p521Priv.X.FillBytes(make([]byte, 66))
	y521 := p521Priv.Y.FillBytes(make([]byte, 66))
	x521B64 := base64.RawURLEncoding.EncodeToString(x521)
	y521B64 := base64.RawURLEncoding.EncodeToString(y521)

	jwksP521 := []byte(fmt.Sprintf(`{"keys":[{"kty":"EC","kid":"p521-k1","crv":"P-521","alg":"ES512","x":%q,"y":%q}]}`, x521B64, y521B64))
	keys521, err := ParseJWKS(jwksP521)
	if err != nil {
		t.Fatalf("ParseJWKS P-521 failed: %v", err)
	}
	if len(keys521) != 1 || keys521[0].ECDSAPublic == nil || keys521[0].ECDSAPublic.Curve != elliptic.P521() {
		t.Fatalf("unexpected parsed P-521 key: %+v", keys521)
	}

	// UpdateKeysFromJWKS P-521
	v521, _ := New(nil, Options{
		Algorithm: AlgES512,
		Keys:      []Key{{ID: "init", ECDSAPublic: &p521Priv.PublicKey}},
	})
	if err := v521.UpdateKeysFromJWKS(jwksP521); err != nil {
		t.Fatalf("UpdateKeysFromJWKS P-521 failed: %v", err)
	}

	// Adversarial EC cases
	// P-384 with 32-byte coordinates
	shortX := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	badCoordLen := []byte(fmt.Sprintf(`{"keys":[{"kty":"EC","kid":"k","crv":"P-384","x":%q,"y":%q}]}`, shortX, y384B64))
	if _, err := ParseJWKS(badCoordLen); !errors.Is(err, ErrInvalidJWKS) {
		t.Fatalf("expected ErrInvalidJWKS for bad coord len, got %v", err)
	}

	// P-384 off curve
	offCurveY := make([]byte, 48)
	offCurveY[0] = 0x01
	badOffCurve := []byte(fmt.Sprintf(`{"keys":[{"kty":"EC","kid":"k","crv":"P-384","x":%q,"y":%q}]}`, x384B64, base64.RawURLEncoding.EncodeToString(offCurveY)))
	if _, err := ParseJWKS(badOffCurve); !errors.Is(err, ErrInvalidJWKS) {
		t.Fatalf("expected ErrInvalidJWKS for off-curve point, got %v", err)
	}

	// P-521 off curve
	offCurveY521 := make([]byte, 66)
	offCurveY521[0] = 0x01
	badOffCurve521 := []byte(fmt.Sprintf(`{"keys":[{"kty":"EC","kid":"k","crv":"P-521","x":%q,"y":%q}]}`, x521B64, base64.RawURLEncoding.EncodeToString(offCurveY521)))
	if _, err := ParseJWKS(badOffCurve521); !errors.Is(err, ErrInvalidJWKS) {
		t.Fatalf("expected ErrInvalidJWKS for off-curve P-521 point, got %v", err)
	}

	// Unknown crv
	badCrv := []byte(fmt.Sprintf(`{"keys":[{"kty":"EC","kid":"k","crv":"secp256k1","x":%q,"y":%q}]}`, x384B64, y384B64))
	if _, err := ParseJWKS(badCrv); !errors.Is(err, ErrInvalidJWKS) {
		t.Fatalf("expected ErrInvalidJWKS for unknown crv, got %v", err)
	}

	// Inconsistent alg on P-384
	badAlgP384 := []byte(fmt.Sprintf(`{"keys":[{"kty":"EC","kid":"k","crv":"P-384","alg":"ES256","x":%q,"y":%q}]}`, x384B64, y384B64))
	if _, err := ParseJWKS(badAlgP384); !errors.Is(err, ErrInvalidJWKS) {
		t.Fatalf("expected ErrInvalidJWKS for inconsistent alg on P-384, got %v", err)
	}
}

func TestV230_DER_Conversions(t *testing.T) {
	// P-521 coordinates with high bit set -> seqLen = 2 + 67 + 2 + 67 = 138 >= 128
	rLong := bytes.Repeat([]byte{0x85}, 66)
	sLong := bytes.Repeat([]byte{0x92}, 66)
	var derBuf [144]byte

	der, ok := encodeP1363ToDER(&derBuf, rLong, sLong, 66)
	if !ok || len(der) == 0 {
		t.Fatal("expected encodeP1363ToDER ok for P-521")
	}
	if der[0] != 0x30 || der[1] != 0x81 || int(der[2]) != 138 {
		t.Fatalf("expected DER long-form sequence tag 0x30 0x81 138, got %x", der[:3])
	}

	// Decode back to raw 132 bytes
	var rawP521 [132]byte
	if !decodeDERToP1363(der, rawP521[:]) {
		t.Fatal("expected decodeDERToP1363 ok for long-form sequence")
	}
	if !bytes.Equal(rawP521[:66], rLong) || !bytes.Equal(rawP521[66:], sLong) {
		t.Fatal("roundtrip P-521 coordinates mismatch")
	}

	// Buffer too small for encodeP1363ToDERInto
	var tinyDst [10]byte
	if _, ok := encodeP1363ToDERInto(tinyDst[:], rLong, sLong, 66); ok {
		t.Fatal("expected false for tiny destination buffer")
	}

	// Truncated buffer in decodeDERToP1363 where idx+1 >= len(der)
	truncDER := []byte{0x30, 0x81, 0x02} // length 3, idx becomes 3, idx+1 >= 3
	if decodeDERToP1363(truncDER, rawP521[:]) {
		t.Fatal("expected false for truncated DER")
	}
}

func TestV230_AdditionalCoverage(t *testing.T) {
	// Test cloneRSAPublicKey(nil)
	if cloneRSAPublicKey(nil) != nil {
		t.Fatal("expected nil for cloneRSAPublicKey(nil)")
	}
	// Test cloneRSAPublicKey with nil N
	clonedNilN := cloneRSAPublicKey(&rsa.PublicKey{E: 65537})
	if clonedNilN == nil || clonedNilN.N != nil {
		t.Fatal("expected clone with nil N")
	}

	// Test isValidRSAPublicKey(nil)
	if isValidRSAPublicKey(nil) {
		t.Fatal("expected false for nil RSA pub")
	}

	// Test isValidP384PublicKey(nil)
	if isValidP384PublicKey(nil) {
		t.Fatal("expected false for nil P-384 pub")
	}
	// Test isValidP521PublicKey(nil)
	if isValidP521PublicKey(nil) {
		t.Fatal("expected false for nil P-521 pub")
	}

	// Test CanSign for destroyed verifier
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	v, _ := NewRS256Verifier(&rsaPriv.PublicKey, rsaPriv)
	v.Destroy()
	if v.CanSign() {
		t.Fatal("expected CanSign false after Destroy")
	}

	// Test SignToIOVWithScratch on destroyed verifier
	var iov [2][]byte
	if err := v.SignToIOVWithScratch(nil, []byte("{}"), &iov, v.NewScratch()); !errors.Is(err, ErrVerifierDestroyed) {
		t.Fatalf("expected ErrVerifierDestroyed, got %v", err)
	}

	// Test SignToIOVWithScratch without signing key
	vVerifyOnly, _ := NewRS256Verifier(&rsaPriv.PublicKey, nil)
	if err := vVerifyOnly.SignToIOVWithScratch(nil, []byte("{}"), &iov, vVerifyOnly.NewScratch()); !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("expected ErrNoSigningKey, got %v", err)
	}

	// Test SignToIOVWithScratch payload too large
	vValid, _ := NewRS256Verifier(&rsaPriv.PublicKey, rsaPriv, Options{MaxPayloadSize: 10})
	if err := vValid.SignToIOVWithScratch(nil, []byte(bytes.Repeat([]byte("a"), 20)), &iov, vValid.NewScratch()); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("expected ErrPayloadTooLarge, got %v", err)
	}

	// Test SignClaimsToIOV on destroyed verifier
	if err := v.SignClaimsToIOV(nil, StandardClaims{Subject: "a", ExpiresAt: 100}, &iov); !errors.Is(err, ErrVerifierDestroyed) {
		t.Fatalf("expected ErrVerifierDestroyed, got %v", err)
	}
	// Test SignClaimsToIOV without signing key
	if err := vVerifyOnly.SignClaimsToIOV(nil, StandardClaims{Subject: "a", ExpiresAt: 100}, &iov); !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("expected ErrNoSigningKey, got %v", err)
	}
	// Test SignClaimsToIOV missing exp
	if err := vValid.SignClaimsToIOV(nil, StandardClaims{Subject: "a", ExpiresAt: 0}, &iov); !errors.Is(err, ErrMissingExp) {
		t.Fatalf("expected ErrMissingExp, got %v", err)
	}
	// Test SignClaimsToIOV invalid payload (empty sub)
	if err := vValid.SignClaimsToIOV(nil, StandardClaims{Subject: "", ExpiresAt: 100}, &iov); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload, got %v", err)
	}
	// Test SignClaimsToIOV invalid payload (long username)
	if err := vValid.SignClaimsToIOV(nil, StandardClaims{Subject: "a", Username: string(bytes.Repeat([]byte("u"), MaxUsernameSize+1)), ExpiresAt: 100}, &iov); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for long username, got %v", err)
	}
	// Test SignClaimsToIOV invalid payload (long iss)
	if err := vValid.SignClaimsToIOV(nil, StandardClaims{Subject: "a", Issuer: string(bytes.Repeat([]byte("i"), MaxIssuerSize+1)), ExpiresAt: 100}, &iov); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for long issuer, got %v", err)
	}
	// Test SignClaimsToIOV invalid payload (long aud)
	if err := vValid.SignClaimsToIOV(nil, StandardClaims{Subject: "a", Audience: string(bytes.Repeat([]byte("a"), MaxAudienceSize+1)), ExpiresAt: 100}, &iov); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for long audience, got %v", err)
	}
	// Test SignClaimsToIOV invalid payload (long jti)
	if err := vValid.SignClaimsToIOV(nil, StandardClaims{Subject: "a", JTI: string(bytes.Repeat([]byte("j"), MaxJTISize+1)), ExpiresAt: 100}, &iov); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for long JTI, got %v", err)
	}

	// ErrSigningFailed with errReader on ES384, ES512, RS256
	p384Priv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	vES384, _ := NewES384Verifier(&p384Priv.PublicKey, p384Priv)
	vES384.randReader = errReader{}
	if _, err := vES384.Sign(nil, []byte(`{"sub":"a"}`)); !errors.Is(err, ErrSigningFailed) {
		t.Fatalf("expected ErrSigningFailed for ES384, got %v", err)
	}
	if err := vES384.SignToIOV(nil, []byte(`{"sub":"a"}`), &iov); !errors.Is(err, ErrSigningFailed) {
		t.Fatalf("expected ErrSigningFailed for ES384 IOV, got %v", err)
	}

	p521Priv, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	vES512, _ := NewES512Verifier(&p521Priv.PublicKey, p521Priv)
	vES512.randReader = errReader{}
	if _, err := vES512.Sign(nil, []byte(`{"sub":"a"}`)); !errors.Is(err, ErrSigningFailed) {
		t.Fatalf("expected ErrSigningFailed for ES512, got %v", err)
	}
	if err := vES512.SignToIOV(nil, []byte(`{"sub":"a"}`), &iov); !errors.Is(err, ErrSigningFailed) {
		t.Fatalf("expected ErrSigningFailed for ES512 IOV, got %v", err)
	}

	vRSASignFail, _ := NewRS256Verifier(&rsaPriv.PublicKey, rsaPriv)
	vRSASignFail.rsaPriv = &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: big.NewInt(1), E: 65537}, D: big.NewInt(1)}
	if _, err := vRSASignFail.Sign(nil, []byte(`{"sub":"a"}`)); !errors.Is(err, ErrSigningFailed) {
		t.Fatalf("expected ErrSigningFailed for RS256, got %v", err)
	}
	if err := vRSASignFail.SignToIOV(nil, []byte(`{"sub":"a"}`), &iov); !errors.Is(err, ErrSigningFailed) {
		t.Fatalf("expected ErrSigningFailed for RS256 IOV, got %v", err)
	}

	// JWKS e with BitLen > 31
	e5Bytes := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 0, 0, 1})
	nB64 := base64.RawURLEncoding.EncodeToString(rsaPriv.N.Bytes())
	badEBitLen := []byte(fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":"bad-ebit","n":%q,"e":%q}]}`, nB64, e5Bytes))
	if _, err := ParseJWKS(badEBitLen); !errors.Is(err, ErrInvalidJWKS) {
		t.Fatalf("expected ErrInvalidJWKS for e bitLen > 31, got %v", err)
	}

	// validateConfig with bad PublicKey on private key
	p256Key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := New(nil, Options{Algorithm: AlgES384, ECDSAPrivateKey: &ecdsa.PrivateKey{PublicKey: p256Key.PublicKey, D: big.NewInt(1)}}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for bad priv pub key in ES384, got %v", err)
	}
	if _, err := New(nil, Options{Algorithm: AlgES512, ECDSAPrivateKey: &ecdsa.PrivateKey{PublicKey: p256Key.PublicKey, D: big.NewInt(1)}}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for bad priv pub key in ES512, got %v", err)
	}
	shortPriv, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := New(nil, Options{Algorithm: AlgRS256, RSAPrivateKey: shortPriv}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for 1024-bit RSA priv key, got %v", err)
	}

	// validateKeysList with unsupported algorithm
	if err := validateKeysList([]Key{{ID: "k1"}}, Algorithm("UNSUPPORTED_ALG"), false); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for unsupported alg in validateKeysList, got %v", err)
	}

	// Verify and VerifySplit with nil pub keys
	vDefault, _ := NewRS256Verifier(&rsaPriv.PublicKey, rsaPriv)
	st := vDefault.NewScratch()
	dummyTok := []byte("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0." + base64.RawURLEncoding.EncodeToString(make([]byte, 256)))
	vNilRSA := &Verifier{alg: AlgRS256, algBytes: []byte("RS256"), sigDecodedLen: 256, maxHeaderSize: 128, maxPayloadSize: 1024}
	if _, err := vNilRSA.verifySignatureAndDecodePayload(dummyTok, st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for nil RSA pub, got %v", err)
	}
	if _, err := vNilRSA.verifySplitSignatureAndDecodePayload(dummyTok[:10], dummyTok[10:], st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for nil RSA pub split, got %v", err)
	}

	dummyES384 := []byte("eyJhbGciOiJFUzM4NCJ9.eyJzdWIiOiIxIn0." + base64.RawURLEncoding.EncodeToString(make([]byte, 96)))
	vNilES384 := &Verifier{alg: AlgES384, algBytes: []byte("ES384"), sigDecodedLen: 96, maxHeaderSize: 128, maxPayloadSize: 1024}
	if _, err := vNilES384.verifySignatureAndDecodePayload(dummyES384, st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for nil ES384 pub, got %v", err)
	}
	if _, err := vNilES384.verifySplitSignatureAndDecodePayload(dummyES384[:10], dummyES384[10:], st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for nil ES384 pub split, got %v", err)
	}

	dummyES512 := []byte("eyJhbGciOiJFUzUxMiJ9.eyJzdWIiOiIxIn0." + base64.RawURLEncoding.EncodeToString(make([]byte, 132)))
	vNilES512 := &Verifier{alg: AlgES512, algBytes: []byte("ES512"), sigDecodedLen: 132, maxHeaderSize: 128, maxPayloadSize: 1024}
	if _, err := vNilES512.verifySignatureAndDecodePayload(dummyES512, st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for nil ES512 pub, got %v", err)
	}
	if _, err := vNilES512.verifySplitSignatureAndDecodePayload(dummyES512[:10], dummyES512[10:], st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for nil ES512 pub split, got %v", err)
	}

	// All-zero signatures for ES384 and ES512 (causing encodeP1363ToDER to fail)
	vRealES384, _ := NewES384Verifier(&p384Priv.PublicKey, nil)
	if _, err := vRealES384.verifySignatureAndDecodePayload(dummyES384, st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for all-zero ES384 sig, got %v", err)
	}
	if _, err := vRealES384.verifySplitSignatureAndDecodePayload(dummyES384[:10], dummyES384[10:], st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for all-zero ES384 sig split, got %v", err)
	}

	vRealES512, _ := NewES512Verifier(&p521Priv.PublicKey, nil)
	if _, err := vRealES512.verifySignatureAndDecodePayload(dummyES512, st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for all-zero ES512 sig, got %v", err)
	}
	if _, err := vRealES512.verifySplitSignatureAndDecodePayload(dummyES512[:10], dummyES512[10:], st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for all-zero ES512 sig split, got %v", err)
	}
}
