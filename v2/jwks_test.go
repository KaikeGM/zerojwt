package zerojwt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"
	"time"
)

func TestJWKS_ParseAndRotation(t *testing.T) {
	// 1. Generate keys
	hsSecret1 := []byte("secret-number-1-must-be-at-least-32-bytes!!")
	hsSecret2 := []byte("secret-number-2-must-be-at-least-32-bytes!!")
	b64Secret1 := base64.RawURLEncoding.EncodeToString(hsSecret1)
	b64Secret2 := base64.RawURLEncoding.EncodeToString(hsSecret2)

	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b64EdPub := base64.RawURLEncoding.EncodeToString(edPub)

	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xBytes := ecPriv.X.Bytes()
	yBytes := ecPriv.Y.Bytes()
	b64X := base64.RawURLEncoding.EncodeToString(xBytes)
	b64Y := base64.RawURLEncoding.EncodeToString(yBytes)

	// Valid JWKS with all types
	jwksJSON := fmt.Sprintf(`{
		"keys": [
			{"kty": "oct", "kid": "hs-key-1", "k": "%s"},
			{"kty": "oct", "kid": "hs-key-2", "k": "%s"},
			{"kty": "OKP", "kid": "ed-key-1", "crv": "Ed25519", "x": "%s"},
			{"kty": "EC", "kid": "ec-key-1", "crv": "P-256", "x": "%s", "y": "%s"}
		]
	}`, b64Secret1, b64Secret2, b64EdPub, b64X, b64Y)

	keys, err := ParseJWKS([]byte(jwksJSON))
	if err != nil {
		t.Fatalf("ParseJWKS failed: %v", err)
	}
	if len(keys) != 4 {
		t.Fatalf("expected 4 keys, got %d", len(keys))
	}

	// 2. Test live rotation in Verifier
	v, err := New(hsSecret1, Options{
		Keys: []Key{
			{ID: "hs-key-1", Secret: hsSecret1},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	signer1, err := New(hsSecret1, Options{
		ActiveKeyID: "hs-key-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	sc := StandardClaims{
		ExpiresAt: now + 300,
		Subject:   "user-rotation",
	}

	tok1, err := signer1.SignClaims(nil, sc)
	if err != nil {
		t.Fatal(err)
	}

	st := v.NewScratch()
	var out Claims
	if err := v.VerifyWithScratch(tok1, now, &out, st); err != nil {
		t.Fatalf("verify tok1 failed: %v", err)
	}
	// Second verify to hit getOrInitKeyMac cache hit
	if err := v.VerifyWithScratch(tok1, now, &out, st); err != nil {
		t.Fatalf("verify tok1 hit cache failed: %v", err)
	}

	// Sign with a key not yet in Verifier
	signer2, err := New(hsSecret2, Options{
		ActiveKeyID: "hs-key-2",
	})
	if err != nil {
		t.Fatal(err)
	}
	tok2, err := signer2.SignClaims(nil, sc)
	if err != nil {
		t.Fatal(err)
	}

	// Verify tok2 should fail (unknown kid)
	if err := v.VerifyWithScratch(tok2, now, &out, st); err != ErrUnknownKeyID {
		t.Fatalf("expected ErrUnknownKeyID for tok2 before rotation, got %v", err)
	}

	// Update keys from JWKS
	jwksRotation := fmt.Sprintf(`{
		"keys": [
			{"kty": "oct", "kid": "hs-key-1", "k": "%s"},
			{"kty": "oct", "kid": "hs-key-2", "k": "%s"}
		]
	}`, b64Secret1, b64Secret2)

	if err := v.UpdateKeysFromJWKS([]byte(jwksRotation)); err != nil {
		t.Fatalf("UpdateKeysFromJWKS failed: %v", err)
	}

	// Both tok1 and tok2 should now succeed!
	if err := v.VerifyWithScratch(tok2, now, &out, st); err != nil {
		t.Fatalf("verify tok2 failed after rotation: %v", err)
	}
	if err := v.VerifyWithScratch(tok1, now, &out, st); err != nil {
		t.Fatalf("verify tok1 failed after rotation: %v", err)
	}
}

func TestJWKS_ParseJWKSEdgesAndErrors(t *testing.T) {
	badJWKS := []string{
		`not json`,
		`[]`,
		`{"other": 123}`,
		`{"keys": "not an array"}`,
		`{"keys": [123]}`,
		`{"keys": [{"kty": "oct"}]}`,            // missing kid
		`{"keys": [{"kty": "oct", "kid": ""}]}`, // empty kid
		`{"keys": [{"kty": "unknown", "kid": "k1"}]}`,        // unknown kty
		`{"keys": [{"kty": "oct", "kid": "k1"}]}`,            // missing k
		`{"keys": [{"kty": "oct", "kid": "k1", "k": "!!"}]}`, // invalid base64 k
		`{"keys": [{"kty": "oct", "kid": "k1", "k": ""}]}`,   // empty k
		`{"keys": [{"kty": "OKP", "kid": "k1", "crv": "wrong", "x": "dGVzdA"}]}`,
		`{"keys": [{"kty": "OKP", "kid": "k1", "crv": "Ed25519", "x": ""}]}`,
		`{"keys": [{"kty": "OKP", "kid": "k1", "crv": "Ed25519", "x": "!!"}]}`,
		`{"keys": [{"kty": "OKP", "kid": "k1", "crv": "Ed25519", "x": "dGVzdA"}]}`, // wrong size (4 bytes != 32)
		`{"keys": [{"kty": "EC", "kid": "k1", "crv": "P-384", "x": "dGVzdA", "y": "dGVzdA"}]}`,
		`{"keys": [{"kty": "EC", "kid": "k1", "crv": "P-256", "x": "", "y": "dGVzdA"}]}`,
		`{"keys": [{"kty": "EC", "kid": "k1", "crv": "P-256", "x": "dGVzdA", "y": ""}]}`,
		`{"keys": [{"kty": "EC", "kid": "k1", "crv": "P-256", "x": "!!", "y": "dGVzdA"}]}`,
		`{"keys": [{"kty": "EC", "kid": "k1", "crv": "P-256", "x": "dGVzdA", "y": "!!"}]}`,
		// Point not on curve P-256:
		fmt.Sprintf(`{"keys": [{"kty": "EC", "kid": "k1", "crv": "P-256", "x": "%s", "y": "%s"}]}`,
			base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
			base64.RawURLEncoding.EncodeToString(make([]byte, 32))),
		`{"keys": [{bad_json}]}`,
		`{"keys": [{"kty": 123}]`,
		`{"keys": [{}`,
		fmt.Sprintf(`{"keys": [{"kty": "oct", "kid": "k1", "k": "%s"}, :]}`, base64.RawURLEncoding.EncodeToString([]byte("01234567890123456789012345678901"))),
	}

	for _, input := range badJWKS {
		if _, err := ParseJWKS([]byte(input)); err == nil {
			t.Errorf("expected error for bad JWKS %q, got nil", input)
		}
	}

	// Test non-string property inside JWKS key (covers !isStr branch) and escaped kid
	extraPropsJWKS := `{"keys": [{"kty": "oct", "kid": "k\"1", "k": "c2VjcmV0LWtleS0zMi1ieXRlcy1sb25nISEhISEhIQ", "use_count": 42, "active": true}]}`
	keys, err := ParseJWKS([]byte(extraPropsJWKS))
	if err != nil {
		t.Fatalf("failed to parse JWKS with extra non-string properties: %v", err)
	}
	if len(keys) != 1 || keys[0].ID != `k"1` {
		t.Fatalf("expected unescaped kid %q, got %q", `k"1`, keys[0].ID)
	}

	// Test token with kid against a verifier with no keys configured (len(keys) == 0)
	noKeysVerifier, err := New([]byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}
	kidSigner, err := New([]byte("01234567890123456789012345678901"), Options{
		ActiveKeyID: "my-kid",
	})
	if err != nil {
		t.Fatal(err)
	}
	kidTok, err := kidSigner.SignClaims(nil, StandardClaims{ExpiresAt: time.Now().Unix() + 100, Subject: "test"})
	if err != nil {
		t.Fatal(err)
	}
	var c Claims
	if err := noKeysVerifier.Verify(kidTok, time.Now().Unix(), &c); err != ErrUnknownKeyID {
		t.Fatalf("expected ErrUnknownKeyID, got %v", err)
	}
}

func TestUpdateKeys_EdgeCases(t *testing.T) {
	v, err := New([]byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}

	// 1. Destroyed verifier
	v.Destroy()
	if err := v.UpdateKeys([]Key{{ID: "k1", Secret: []byte("01234567890123456789012345678901")}}); err != ErrVerifierDestroyed {
		t.Fatalf("expected ErrVerifierDestroyed, got %v", err)
	}

	// 2. Validation errors in validateKeysList
	v2, err := New([]byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatal(err)
	}

	// Empty ID
	if err := v2.UpdateKeys([]Key{{ID: "", Secret: []byte("01234567890123456789012345678901")}}); err == nil {
		t.Error("expected error for empty Key ID")
	}

	// Duplicate ID
	if err := v2.UpdateKeys([]Key{
		{ID: "dup", Secret: []byte("01234567890123456789012345678901")},
		{ID: "dup", Secret: []byte("01234567890123456789012345678901")},
	}); err == nil {
		t.Error("expected error for duplicate Key ID")
	}

	// Empty Secret for HS256
	if err := v2.UpdateKeys([]Key{{ID: "k1", Secret: nil}}); err == nil {
		t.Error("expected error for empty secret")
	}

	// Short Secret for HS256 (strictSecret is true)
	if err := v2.UpdateKeys([]Key{{ID: "k1", Secret: []byte("short")}}); err == nil {
		t.Error("expected error for short secret under strictSecret")
	}

	// EdDSA verifier with invalid Ed25519Public
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edV, err := NewEd25519Verifier(pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := edV.UpdateKeys([]Key{{ID: "k1", Ed25519Public: []byte("short")}}); err == nil {
		t.Error("expected error for invalid Ed25519Public length")
	}

	// ES256 verifier with invalid ECDSAPublic
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	esV, err := NewES256Verifier(&ecPriv.PublicKey, ecPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := esV.UpdateKeys([]Key{{ID: "k1", ECDSAPublic: nil}}); err == nil {
		t.Error("expected error for nil ECDSAPublic")
	}
	// Wrong curve (P-384)
	ec384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := esV.UpdateKeys([]Key{{ID: "k1", ECDSAPublic: &ec384.PublicKey}}); err == nil {
		t.Error("expected error for wrong curve ECDSAPublic")
	}

	// Unsupported algorithm
	unsupportedV := &Verifier{alg: "RS256"}
	if err := unsupportedV.UpdateKeys([]Key{{ID: "k1"}}); err == nil {
		t.Error("expected error for unsupported algorithm in UpdateKeys")
	}

	// UpdateKeysFromJWKS with invalid JWKS
	if err := v2.UpdateKeysFromJWKS([]byte("invalid-jwks")); err == nil {
		t.Error("expected error for invalid JWKS in UpdateKeysFromJWKS")
	}
}

func TestJWKS_BufferImmutability(t *testing.T) {
	// A JWKS containing an escaped kid string like "k\"ey\\1"
	raw := []byte(`{"keys":[{"kty":"oct","kid":"k\"ey\\1","k":"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE"}]}`)
	rawCopy := make([]byte, len(raw))
	copy(rawCopy, raw)

	keys, err := ParseJWKS(raw)
	if err != nil {
		t.Fatalf("ParseJWKS failed: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if !bytes.Equal(raw, rawCopy) {
		t.Fatalf("ParseJWKS mutated input buffer: before=%q, after=%q", string(rawCopy), string(raw))
	}
}

func TestJWKS_RFC7517_Interoperability(t *testing.T) {
	// JWKS containing an RSA key, an encryption key ("use": "enc"), and a valid oct key
	mixedJWKS := []byte(`{
		"keys": [
			{"kty": "RSA", "kid": "rsa-1", "n": "abc", "e": "AQAB"},
			{"kty": "oct", "kid": "enc-key", "use": "enc", "k": "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE"},
			{"kty": "oct", "kid": "sig-key", "use": "sig", "k": "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE"}
		]
	}`)
	keys, err := ParseJWKS(mixedJWKS)
	if err != nil {
		t.Fatalf("ParseJWKS failed on mixed JWKS: %v", err)
	}
	if len(keys) != 1 || keys[0].ID != "sig-key" {
		t.Fatalf("expected 1 valid key with ID 'sig-key', got %+v", keys)
	}

	// JWKS with only unsupported keys or enc keys -> ErrInvalidJWKS
	onlyRSA := []byte(`{"keys":[{"kty":"RSA","kid":"rsa-1","n":"abc"}]}`)
	if _, err := ParseJWKS(onlyRSA); err != ErrInvalidJWKS {
		t.Fatalf("expected ErrInvalidJWKS for RSA-only JWKS, got %v", err)
	}

	onlyEnc := []byte(`{"keys":[{"kty":"oct","kid":"e1","use":"enc","k":"MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE"}]}`)
	if _, err := ParseJWKS(onlyEnc); err != ErrInvalidJWKS {
		t.Fatalf("expected ErrInvalidJWKS for enc-only JWKS, got %v", err)
	}
}

func TestJWKS_KeyOpsAndAlgValidation(t *testing.T) {
	validSec := base64.RawURLEncoding.EncodeToString([]byte("01234567890123456789012345678901"))

	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b64EdPub := base64.RawURLEncoding.EncodeToString(edPub)

	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var xBuf, yBuf [32]byte
	ecPriv.X.FillBytes(xBuf[:])
	ecPriv.Y.FillBytes(yBuf[:])
	b64X := base64.RawURLEncoding.EncodeToString(xBuf[:])
	b64Y := base64.RawURLEncoding.EncodeToString(yBuf[:])

	// 1. Valid key_ops combinations and algorithm matches
	validCases := []string{
		// oct with verify only
		fmt.Sprintf(`{"keys": [{"kty": "oct", "kid": "k1", "k": "%s", "key_ops": ["verify"], "alg": "HS256"}]}`, validSec),
		// oct with sign and verify
		fmt.Sprintf(`{"keys": [{"kty": "oct", "kid": "k2", "k": "%s", "key_ops": ["sign", "verify"], "alg": "HS384"}]}`, validSec),
		fmt.Sprintf(`{"keys": [{"kty": "oct", "kid": "k3", "k": "%s", "key_ops": ["verify"], "alg": "HS512"}]}`, validSec),
		// OKP with EdDSA
		fmt.Sprintf(`{"keys": [{"kty": "OKP", "kid": "k4", "crv": "Ed25519", "x": "%s", "key_ops": ["verify"], "alg": "EdDSA"}]}`, b64EdPub),
		// EC with ES256
		fmt.Sprintf(`{"keys": [{"kty": "EC", "kid": "k5", "crv": "P-256", "x": "%s", "y": "%s", "key_ops": ["verify"], "alg": "ES256"}]}`, b64X, b64Y),
		// Skipping non-verifying key (key_ops: ["encrypt"]) when another valid key exists
		fmt.Sprintf(`{"keys": [
			{"kty": "oct", "kid": "k-enc", "k": "%s", "key_ops": ["encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits"]},
			{"kty": "oct", "kid": "k-sig", "k": "%s", "key_ops": ["verify"]}
		]}`, validSec, validSec),
	}

	for i, jwks := range validCases {
		keys, err := ParseJWKS([]byte(jwks))
		if err != nil {
			t.Fatalf("case %d: expected success, got error %v", i, err)
		}
		if len(keys) == 0 {
			t.Fatalf("case %d: expected keys, got 0", i)
		}
	}

	// 2. Invalid JWKS cases covering RFC 7517 / RFC 7518 rules and Wycheproof vectors
	invalidCases := []string{
		// key_ops is string instead of array
		fmt.Sprintf(`{"keys": [{"kty": "oct", "kid": "k1", "k": "%s", "key_ops": "verify"}]}`, validSec),
		// key_ops is not array
		fmt.Sprintf(`{"keys": [{"kty": "oct", "kid": "k1", "k": "%s", "key_ops": 123}]}`, validSec),
		// key_ops is empty array
		fmt.Sprintf(`{"keys": [{"kty": "oct", "kid": "k1", "k": "%s", "key_ops": []}]}`, validSec),
		// key_ops contains non-string
		fmt.Sprintf(`{"keys": [{"kty": "oct", "kid": "k1", "k": "%s", "key_ops": [123]}]}`, validSec),
		// key_ops contains empty string
		fmt.Sprintf(`{"keys": [{"kty": "oct", "kid": "k1", "k": "%s", "key_ops": [""]}]}`, validSec),
		// key_ops contains unknown op
		fmt.Sprintf(`{"keys": [{"kty": "oct", "kid": "k1", "k": "%s", "key_ops": ["unknown"]}]}`, validSec),
		// use: "sig" with encrypt key_ops
		fmt.Sprintf(`{"keys": [{"kty": "oct", "kid": "k1", "k": "%s", "use": "sig", "key_ops": ["encrypt"]}]}`, validSec),
		// use: "enc" with verify key_ops
		fmt.Sprintf(`{"keys": [{"kty": "oct", "kid": "k1", "k": "%s", "use": "enc", "key_ops": ["verify"]}]}`, validSec),
		// use: "enc" with sign key_ops
		fmt.Sprintf(`{"keys": [{"kty": "oct", "kid": "k1", "k": "%s", "use": "enc", "key_ops": ["sign"]}]}`, validSec),
		// invalid use string
		fmt.Sprintf(`{"keys": [{"kty": "oct", "kid": "k1", "k": "%s", "use": "invalid"}]}`, validSec),
		// empty use string
		fmt.Sprintf(`{"keys": [{"kty": "oct", "kid": "k1", "k": "%s", "use": ""}]}`, validSec),
		// non-string property types:
		fmt.Sprintf(`{"keys": [{"kty": 123, "kid": "k1", "k": "%s"}]}`, validSec),
		fmt.Sprintf(`{"keys": [{"kty": "oct", "kid": 123, "k": "%s"}]}`, validSec),
		fmt.Sprintf(`{"keys": [{"kty": "oct", "kid": "k1", "use": 123, "k": "%s"}]}`, validSec),
		fmt.Sprintf(`{"keys": [{"kty": "oct", "kid": "k1", "alg": 123, "k": "%s"}]}`, validSec),
		fmt.Sprintf(`{"keys": [{"kty": "OKP", "kid": "k1", "crv": 123, "x": "%s"}]}`, b64EdPub),
		fmt.Sprintf(`{"keys": [{"kty": "oct", "kid": "k1", "k": 123}]}`),
		fmt.Sprintf(`{"keys": [{"kty": "OKP", "kid": "k1", "crv": "Ed25519", "x": 123}]}`),
		fmt.Sprintf(`{"keys": [{"kty": "EC", "kid": "k1", "crv": "P-256", "x": "%s", "y": 123}]}`, b64X),
		// empty alg
		fmt.Sprintf(`{"keys": [{"kty": "oct", "kid": "k1", "k": "%s", "alg": ""}]}`, validSec),
		// mismatched alg
		fmt.Sprintf(`{"keys": [{"kty": "oct", "kid": "k1", "k": "%s", "alg": "ES256"}]}`, validSec),
		fmt.Sprintf(`{"keys": [{"kty": "OKP", "kid": "k1", "crv": "Ed25519", "x": "%s", "alg": "HS256"}]}`, b64EdPub),
		fmt.Sprintf(`{"keys": [{"kty": "EC", "kid": "k1", "crv": "P-256", "x": "%s", "y": "%s", "alg": "HS256"}]}`, b64X, b64Y),
		// duplicate kid
		fmt.Sprintf(`{"keys": [
			{"kty": "oct", "kid": "dup-id", "k": "%s"},
			{"kty": "oct", "kid": "dup-id", "k": "%s"}
		]}`, validSec, validSec),
		// Base64 with carriage return or newline
		fmt.Sprintf(`{"keys": [{"kty": "oct", "kid": "k1", "k": "MDEyMzQ1Njc4OTAxMjM0NTY3OD\nkwMTIzNDU2Nzg5MDE"}]}`),
		fmt.Sprintf(`{"keys": [{"kty": "oct", "kid": "k1", "k": "MDEyMzQ1Njc4OTAxMjM0NTY3OD\rkwMTIzNDU2Nzg5MDE"}]}`),
		// EC coordinate lengths not exactly 32 octets (RFC 7518 §6.2.1.2 Wycheproof vectors):
		// 31-byte X coordinate
		fmt.Sprintf(`{"keys": [{"kty": "EC", "kid": "k1", "crv": "P-256", "x": "%s", "y": "%s"}]}`,
			base64.RawURLEncoding.EncodeToString(make([]byte, 31)), b64Y),
		// 33-byte X coordinate
		fmt.Sprintf(`{"keys": [{"kty": "EC", "kid": "k1", "crv": "P-256", "x": "%s", "y": "%s"}]}`,
			base64.RawURLEncoding.EncodeToString(make([]byte, 33)), b64Y),
		// 31-byte Y coordinate
		fmt.Sprintf(`{"keys": [{"kty": "EC", "kid": "k1", "crv": "P-256", "x": "%s", "y": "%s"}]}`,
			b64X, base64.RawURLEncoding.EncodeToString(make([]byte, 31))),
		// 33-byte Y coordinate
		fmt.Sprintf(`{"keys": [{"kty": "EC", "kid": "k1", "crv": "P-256", "x": "%s", "y": "%s"}]}`,
			b64X, base64.RawURLEncoding.EncodeToString(make([]byte, 33))),
		// Invalid base64 in Y
		fmt.Sprintf(`{"keys": [{"kty": "EC", "kid": "k1", "crv": "P-256", "x": "%s", "y": "!!!"}]}`, b64X),
	}

	for i, jwks := range invalidCases {
		if _, err := ParseJWKS([]byte(jwks)); err == nil {
			t.Errorf("case %d: expected error for invalid JWKS %s, got nil", i, jwks)
		}
	}
}
