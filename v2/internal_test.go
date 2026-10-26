package zerojwt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestInternalDERConversion(t *testing.T) {
	var derBuf [144]byte

	// encodeP1363ToDER with empty r or s
	if _, ok := encodeP1363ToDER(&derBuf, nil, []byte("s")); ok {
		t.Fatal("expected failure on empty r")
	}
	if _, ok := encodeP1363ToDER(&derBuf, []byte("r"), nil); ok {
		t.Fatal("expected failure on empty s")
	}
	// encodeP1363ToDER with leading zeros and padding
	rWithPad := []byte{0x00, 0x85, 0x01}
	sWithPad := []byte{0x00, 0x90, 0x02}
	der, ok := encodeP1363ToDER(&derBuf, rWithPad, sWithPad)
	if !ok || len(der) == 0 {
		t.Fatal("expected ok for r/s with leading zero and high bit set")
	}

	// decodeDERToP1363 edge cases
	var rawSig [64]byte
	if decodeDERToP1363([]byte{0x30, 0x02}, rawSig[:]) {
		t.Fatal("expected decode failure on short DER (< 8 bytes)")
	}
	if decodeDERToP1363([]byte{0x31, 0x08, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}, rawSig[:]) {
		t.Fatal("expected decode failure on non-0x30 sequence tag")
	}
	if decodeDERToP1363([]byte{0x30, 0x08, 0x03, 0x01, 0x01, 0x02, 0x01, 0x01}, rawSig[:]) {
		t.Fatal("expected decode failure on non-INTEGER r tag")
	}
	if decodeDERToP1363([]byte{0x30, 0x08, 0x02, 0x05, 0x01, 0x02, 0x01, 0x01}, rawSig[:]) {
		t.Fatal("expected decode failure on truncated r bytes")
	}
	if decodeDERToP1363([]byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x03, 0x01, 0x01}, rawSig[:]) {
		t.Fatal("expected decode failure on non-INTEGER s tag")
	}
	if decodeDERToP1363([]byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x05, 0x01}, rawSig[:]) {
		t.Fatal("expected decode failure on truncated s bytes")
	}

	// Oversized r (> 32 non-zero bytes)
	longR := bytes.Repeat([]byte{0x01}, 33)
	derLongR := append([]byte{0x30, byte(4 + len(longR)), 0x02, byte(len(longR))}, longR...)
	derLongR = append(derLongR, 0x02, 0x01, 0x01)
	if decodeDERToP1363(derLongR, rawSig[:]) {
		t.Fatal("expected decode failure on r > 32 bytes")
	}

	// Oversized s (> 32 non-zero bytes)
	longS := bytes.Repeat([]byte{0x01}, 33)
	derLongS := []byte{0x30, byte(4 + len(longS)), 0x02, 0x01, 0x01, 0x02, byte(len(longS))}
	derLongS = append(derLongS, longS...)
	if decodeDERToP1363(derLongS, rawSig[:]) {
		t.Fatal("expected decode failure on s > 32 bytes")
	}

	// Long form length (der[1] & 0x80 != 0)
	derLongForm := []byte{0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}
	if !decodeDERToP1363(derLongForm, rawSig[:]) {
		t.Fatal("expected decode success on long form DER length")
	}
}

func TestInternalAudienceMatching(t *testing.T) {
	var capAud []byte

	// String audience match & mismatch & escaped
	if !matchAudienceClaim([]byte("api.service"), true, []byte("api.service"), &capAud) {
		t.Fatal("expected match for string audience")
	}
	if matchAudienceClaim([]byte("wrong.service"), true, []byte("api.service"), &capAud) {
		t.Fatal("expected mismatch for wrong string audience")
	}
	if !matchAudienceClaim([]byte(`api\u002eservice`), true, []byte("api.service"), &capAud) {
		t.Fatal("expected match for escaped string audience")
	}

	// Array audience
	if matchAudienceClaim([]byte("not-an-array"), false, []byte("api.service"), &capAud) {
		t.Fatal("expected false for invalid array syntax")
	}
	if matchAudienceClaim([]byte("[]"), false, []byte("api.service"), &capAud) {
		t.Fatal("expected false for empty array")
	}
	if matchAudienceClaim([]byte(`["admin", 123]`), false, []byte("admin"), &capAud) {
		t.Fatal("expected false for array with non-string elements")
	}
	// Array match first element
	if !matchAudienceClaim([]byte(`["api.service", "backup"]`), false, []byte("api.service"), &capAud) {
		t.Fatal("expected match for array 1st element")
	}
	// Array match second element
	if !matchAudienceClaim([]byte(`["other", "api.service"]`), false, []byte("api.service"), &capAud) {
		t.Fatal("expected match for array 2nd element")
	}
	// Array mismatch all elements
	if matchAudienceClaim([]byte(`["other1", "other2"]`), false, []byte("api.service"), &capAud) {
		t.Fatal("expected mismatch for array with no matching elements")
	}
	// Array without expectedAud matches first element
	if !matchAudienceClaim([]byte(`["first-aud"]`), false, nil, &capAud) {
		t.Fatal("expected match when expectedAud is empty")
	}
	if string(capAud) != "first-aud" {
		t.Fatalf("expected captured first-aud, got %s", string(capAud))
	}
}

func TestInternalParseStandardClaimsEdges(t *testing.T) {
	secret := bytes.Repeat([]byte("s"), 32)
	v, err := New(secret, Options{
		ExpectedIssuer:   "auth.test",
		ExpectedAudience: "api.test",
	})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	var cl Claims

	// Duplicate claims
	if err := v.parseStandardClaims([]byte(fmt.Sprintf(`{"sub":"u","exp":%d,"exp":%d}`, now+1000, now+2000)), now, &cl); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for duplicate exp, got %v", err)
	}
	if err := v.parseStandardClaims([]byte(fmt.Sprintf(`{"sub":"u","nbf":%d,"nbf":%d}`, now-1000, now-500)), now, &cl); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for duplicate nbf, got %v", err)
	}
	if err := v.parseStandardClaims([]byte(`{"sub":"u","iat":100,"iat":200}`), now, &cl); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for duplicate iat, got %v", err)
	}
	if err := v.parseStandardClaims([]byte(`{"sub":"u","sub":"u2"}`), now, &cl); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for duplicate sub, got %v", err)
	}
	if err := v.parseStandardClaims([]byte(`{"sub":"u","username":"a","username":"b"}`), now, &cl); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for duplicate username, got %v", err)
	}
	if err := v.parseStandardClaims([]byte(`{"sub":"u","iss":"auth.test","iss":"auth.test"}`), now, &cl); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for duplicate iss, got %v", err)
	}
	if err := v.parseStandardClaims([]byte(`{"sub":"u","aud":"api.test","aud":"api.test"}`), now, &cl); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for duplicate aud, got %v", err)
	}
	if err := v.parseStandardClaims([]byte(`{"sub":"u","jti":"a","jti":"b"}`), now, &cl); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for duplicate jti, got %v", err)
	}

	// Boolean / invalid type claims
	if err := v.parseStandardClaims([]byte(`{"sub":"u","exp":true}`), now, &cl); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for boolean exp, got %v", err)
	}
	if err := v.parseStandardClaims([]byte(`{"sub":"u","nbf":true}`), now, &cl); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for boolean nbf, got %v", err)
	}
	if err := v.parseStandardClaims([]byte(`{"sub":"u","iat":true}`), now, &cl); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for boolean iat, got %v", err)
	}
	if err := v.parseStandardClaims([]byte(`{"sub":123}`), now, &cl); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for numeric sub, got %v", err)
	}
	if err := v.parseStandardClaims([]byte(`{"sub":"u","username":123}`), now, &cl); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for numeric username, got %v", err)
	}
	if err := v.parseStandardClaims([]byte(`{"sub":"u","iss":123}`), now, &cl); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for numeric iss, got %v", err)
	}
	if err := v.parseStandardClaims([]byte(`{"sub":"u","jti":123}`), now, &cl); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for numeric jti, got %v", err)
	}

	// Buffer overflows
	longSub := string(bytes.Repeat([]byte("s"), 257))
	if err := v.parseStandardClaims([]byte(`{"sub":"`+longSub+`"}`), now, &cl); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for sub > 256, got %v", err)
	}
	longUser := string(bytes.Repeat([]byte("u"), 129))
	if err := v.parseStandardClaims([]byte(`{"sub":"u","username":"`+longUser+`"}`), now, &cl); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for username > 128, got %v", err)
	}
	longIss := string(bytes.Repeat([]byte("i"), 257))
	if err := v.parseStandardClaims([]byte(`{"sub":"u","iss":"`+longIss+`"}`), now, &cl); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for iss > 256, got %v", err)
	}
	vNoAud, _ := New(secret)
	longAud := string(bytes.Repeat([]byte("a"), 257))
	if err := vNoAud.parseStandardClaims([]byte(`{"sub":"u","aud":"`+longAud+`"}`), now, &cl); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for aud > 256, got %v", err)
	}
	longJti := string(bytes.Repeat([]byte("j"), 65))
	if err := v.parseStandardClaims([]byte(`{"sub":"u","jti":"`+longJti+`"}`), now, &cl); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for jti > 64, got %v", err)
	}

	// Escaped unicode values in claims
	if err := v.parseStandardClaims([]byte(fmt.Sprintf(`{"sub":"\u0075\u0031","username":"\u0061","iss":"auth\u002etest","aud":"api\u002etest","jti":"\u0063","exp":%d}`, now+1000)), now, &cl); err != nil {
		t.Fatalf("expected success with escaped claims, got %v", err)
	}
	if string(cl.Subject()) != "u1" || string(cl.Username()) != "a" || string(cl.Issuer()) != "auth.test" || string(cl.Audience()) != "api.test" || string(cl.JTI()) != "c" {
		t.Fatalf("unexpected unescaped claims: %v", cl)
	}

	// Missing iss or aud
	if err := v.parseStandardClaims([]byte(`{"sub":"u","aud":"api.test"}`), now, &cl); !errors.Is(err, ErrInvalidIssuer) {
		t.Fatalf("expected ErrInvalidIssuer for missing iss, got %v", err)
	}
	if err := v.parseStandardClaims([]byte(`{"sub":"u","iss":"auth.test"}`), now, &cl); !errors.Is(err, ErrInvalidAudience) {
		t.Fatalf("expected ErrInvalidAudience for missing aud, got %v", err)
	}
}

func TestInternalHeaderValidationEdges(t *testing.T) {
	secret := bytes.Repeat([]byte("s"), 32)
	v, err := New(secret, Options{
		Keys: []Key{
			{ID: "k1", Secret: secret},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Duplicate alg
	if _, err := v.validateHeader([]byte(`{"alg":"HS256","alg":"HS256"}`)); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for duplicate alg, got %v", err)
	}
	// Duplicate typ
	if _, err := v.validateHeader([]byte(`{"alg":"HS256","typ":"JWT","typ":"JWT"}`)); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for duplicate typ, got %v", err)
	}
	// Duplicate kid
	if _, err := v.validateHeader([]byte(`{"alg":"HS256","kid":"k1","kid":"k1"}`)); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for duplicate kid, got %v", err)
	}
	// Escaped kid
	idx, err := v.validateHeader([]byte(`{"alg":"HS256","kid":"k\u0031"}`))
	if err != nil || idx != 0 {
		t.Fatalf("expected valid match for escaped kid, got idx=%d, err=%v", idx, err)
	}
	// kid empty string
	if _, err := v.validateHeader([]byte(`{"alg":"HS256","kid":""}`)); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for empty kid, got %v", err)
	}
	// kid non-string
	if _, err := v.validateHeader([]byte(`{"alg":"HS256","kid":123}`)); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for non-string kid, got %v", err)
	}
	// Crit header
	if _, err := v.validateHeader([]byte(`{"alg":"HS256","crit":["b64"]}`)); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for crit, got %v", err)
	}
	// Wrong alg
	if _, err := v.validateHeader([]byte(`{"alg":"HS384"}`)); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for mismatched alg, got %v", err)
	}
	// Not starting with quote
	if _, err := v.validateHeader([]byte(`{alg:"HS256"}`)); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for unquoted key, got %v", err)
	}
	// Comma without following quote
	if _, err := v.validateHeader([]byte(`{"alg":"HS256",}`)); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for trailing comma, got %v", err)
	}
	if _, err := v.validateHeader([]byte(`{"alg":"HS256", 123}`)); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for non-quote after comma, got %v", err)
	}

	// Structural JSON syntax errors inside nested array/object values
	malformedNestedHeaders := []string{
		`{"alg":"HS256","":[A]}`,
		`{"alg":"HS256","":[tru]}`,
		`{"alg":"HS256","":[1,2,]}`,
		`{"alg":"HS256","":[1 2]}`,
		`{"alg":"HS256","":{1:2}}`,
		`{"alg":"HS256","":[01]}`,
		`{"alg":"HS256","":[1.2.3]}`,
	}
	for _, h := range malformedNestedHeaders {
		if _, err := v.validateHeader([]byte(h)); !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("expected ErrInvalidHeader for malformed nested JSON %s, got %v", h, err)
		}
	}

	// Valid nested structures must succeed
	validNestedHeaders := []string{
		`{"alg":"HS256","":{}}`,
		`{"alg":"HS256","":[]}`,
		`{"alg":"HS256","custom":[1, "two", true, null, {"k": 5}]}`,
	}
	for _, h := range validNestedHeaders {
		if _, err := v.validateHeader([]byte(h)); err != nil {
			t.Fatalf("expected nil error for valid nested JSON %s, got %v", h, err)
		}
	}
}

func TestInternalSignatureAndScratchEdges(t *testing.T) {
	secret := bytes.Repeat([]byte("s"), 32)
	v, err := New(secret)
	if err != nil {
		t.Fatal(err)
	}
	st := v.NewScratch()

	// 1. Dst buffer growth in SignWithScratch
	smallDst := make([]byte, 5, 10)
	tokGrown, err := v.SignWithScratch(smallDst, []byte(`{"sub":"alice","exp":1900000000}`), st)
	if err != nil {
		t.Fatalf("SignWithScratch with buffer growth failed: %v", err)
	}
	if len(tokGrown) <= len(smallDst) {
		t.Fatalf("expected grown buffer, got len %d", len(tokGrown))
	}

	// 2. Oversized payload in verifySignatureAndDecodePayload
	tinyPlV, _ := New(secret, Options{MaxPayloadSize: 10})
	tinySt := tinyPlV.NewScratch()
	tokNorm, _ := v.Sign(nil, []byte(`{"sub":"alice_with_longer_payload","exp":1900000000}`))
	if _, err := tinyPlV.verifySignatureAndDecodePayload(tokNorm, tinySt); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("expected ErrPayloadTooLarge, got %v", err)
	}

	// 3. Oversized header in verifySignatureAndDecodePayload
	tinyHdrV, _ := New(secret, Options{MaxHeaderSize: 10})
	tinyHdrSt := tinyHdrV.NewScratch()
	if _, err := tinyHdrV.verifySignatureAndDecodePayload(tokNorm, tinyHdrSt); !errors.Is(err, ErrHeaderTooLarge) {
		t.Fatalf("expected ErrHeaderTooLarge for oversized header, got %v", err)
	}

	// 4. Invalid base64 in signature
	tokBadSig := append(append([]byte(nil), tokNorm[:bytes.LastIndexByte(tokNorm, '.')+1]...), []byte("not-base64!@#")...)
	if _, err := v.verifySignatureAndDecodePayload(tokBadSig, st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for invalid base64 in sig, got %v", err)
	}

	// 5. Wrong signature length
	shortSig := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	tokShortSig := append(append([]byte(nil), tokNorm[:bytes.LastIndexByte(tokNorm, '.')+1]...), []byte(shortSig)...)
	if _, err := v.verifySignatureAndDecodePayload(tokShortSig, st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for short sig, got %v", err)
	}

	// 6. Signature mismatch
	forgedTok := append([]byte(nil), tokNorm...)
	forgedTok[len(forgedTok)-2] ^= 0xFF
	if _, err := v.verifySignatureAndDecodePayload(forgedTok, st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for tampered sig, got %v", err)
	}

	// 7. EdDSA signature verification failure
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	vEd, _ := NewEd25519Verifier(edPub, edPriv)
	stEd := vEd.NewScratch()
	tokEd, _ := vEd.Sign(nil, []byte(`{"sub":"ed","exp":1900000000}`))
	tokEdBad := append([]byte(nil), tokEd...)
	tokEdBad[len(tokEdBad)-2] ^= 0xFF
	if _, err := vEd.verifySignatureAndDecodePayload(tokEdBad, stEd); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for tampered EdDSA sig, got %v", err)
	}

	// 8. ES256 signature verification failure & zero signature
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	vEc, _ := NewES256Verifier(&ecPriv.PublicKey, ecPriv)
	stEc := vEc.NewScratch()
	tokEc, _ := vEc.Sign(nil, []byte(`{"sub":"ec","exp":1900000000}`))
	tokEcBad := append([]byte(nil), tokEc...)
	tokEcBad[len(tokEcBad)-2] ^= 0xFF
	if _, err := vEc.verifySignatureAndDecodePayload(tokEcBad, stEc); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for tampered ES256 sig, got %v", err)
	}
	zeroSig64 := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	tokEcZeroSig := append(append([]byte(nil), tokEc[:bytes.LastIndexByte(tokEc, '.')+1]...), []byte(zeroSig64)...)
	if _, err := vEc.verifySignatureAndDecodePayload(tokEcZeroSig, stEc); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for all-zero ES256 sig, got %v", err)
	}

	// 9. Key rotation with empty secret or missing key
	keyRotV, _ := New(secret, Options{
		Keys: []Key{
			{ID: "k1", Secret: bytes.Repeat([]byte("1"), 32)},
		},
	})
	stRot := keyRotV.NewScratch()
	tokRot, _ := keyRotV.Sign(nil, []byte(`{"sub":"rot","exp":1900000000}`))
	if _, err := keyRotV.verifySignatureAndDecodePayload(tokRot, stRot); err != nil {
		t.Fatalf("expected verifySignatureAndDecodePayload to succeed on rotated key, got %v", err)
	}

	// 10. Large scratch buffer allocation
	largeV, _ := New(secret, Options{MaxHeaderSize: 512, MaxPayloadSize: 4096})
	stLarge := largeV.NewScratch()
	if len(stLarge.hdrBuf) != 512 || len(stLarge.payloadBuf) != 4096 {
		t.Fatalf("expected large scratch buffers, got hdr=%d pl=%d", len(stLarge.hdrBuf), len(stLarge.payloadBuf))
	}
}

func TestInternalUTF8RuneEncoding(t *testing.T) {
	var buf [8]byte
	// 1-byte
	n := encodeRuneToUTF8(buf[:], 'A')
	if n != 1 || buf[0] != 'A' {
		t.Fatalf("expected 1-byte UTF-8, got %d", n)
	}
	// 2-byte
	n = encodeRuneToUTF8(buf[:], 0x00E9) // 'é'
	if n != 2 {
		t.Fatalf("expected 2-byte UTF-8, got %d", n)
	}
	// 3-byte
	n = encodeRuneToUTF8(buf[:], 0x4E16) // '世'
	if n != 3 {
		t.Fatalf("expected 3-byte UTF-8, got %d", n)
	}
	// 4-byte
	n = encodeRuneToUTF8(buf[:], 0x1F600) // '😀'
	if n != 4 {
		t.Fatalf("expected 4-byte UTF-8, got %d", n)
	}
}
