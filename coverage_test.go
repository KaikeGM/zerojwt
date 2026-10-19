package zerojwt

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestComprehensiveCoverage(t *testing.T) {
	now := time.Now().Unix()
	secret := []byte("coverage-secret-key-32-bytes!!")
	v := NewVerifierWithOptions(secret, Options{
		ExpectedIssuer:   "auth.test",
		ExpectedAudience: "api.test",
	})
	st := v.NewScratch()

	// --- 1. Builder Coverage ---
	t.Run("BuilderEdgeCases", func(t *testing.T) {
		var dst [512]byte
		bScratch := v.NewSignerWithScratch(dst[:0], st)
		bScratch.SetSubject([]byte("user1")).
			SetIssuedAt(now).
			SetClaimBool("is_admin", false).
			SetClaimString("note", "hello")
		tok, err := bScratch.Sign()
		if err != nil {
			t.Fatalf("NewSignerWithScratch Sign failed: %v", err)
		}
		if len(tok) == 0 {
			t.Fatal("expected non-empty token")
		}

		// Sign with b.st == nil
		emptyBuilder := SignBuilder{v: v}
		if _, err := emptyBuilder.Sign(); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for nil Scratch, got %v", err)
		}

		// Sign with oversized payload
		tinyV := NewVerifierWithOptions(secret, Options{MaxPayloadSize: 10})
		tinyB := tinyV.NewSigner(nil)
		tinyB.SetClaimString("long_key", "long_value_that_exceeds_ten_bytes")
		if _, err := tinyB.Sign(); !errors.Is(err, ErrPayloadTooLarge) {
			t.Fatalf("expected ErrPayloadTooLarge, got %v", err)
		}
	})

	// --- 2. Middleware Coverage ---
	t.Run("MiddlewareEdgeCases", func(t *testing.T) {
		// ProtectFunc edge cases
		hf := v.ProtectFunc(func(w http.ResponseWriter, r *http.Request, c *Claims) {
			w.WriteHeader(http.StatusOK)
		})

		// Missing/short header
		reqNoAuth := httptest.NewRequest(http.MethodGet, "/", nil)
		recNoAuth := httptest.NewRecorder()
		hf(recNoAuth, reqNoAuth)
		if recNoAuth.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for missing auth, got %d", recNoAuth.Code)
		}

		reqShort := httptest.NewRequest(http.MethodGet, "/", nil)
		reqShort.Header.Set("Authorization", "Bear")
		recShort := httptest.NewRecorder()
		hf(recShort, reqShort)
		if recShort.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for short auth, got %d", recShort.Code)
		}

		// Invalid token
		reqBadTok := httptest.NewRequest(http.MethodGet, "/", nil)
		reqBadTok.Header.Set("Authorization", "Bearer invalid.token.payload")
		recBadTok := httptest.NewRecorder()
		hf(recBadTok, reqBadTok)
		if recBadTok.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for bad token, got %d", recBadTok.Code)
		}

		// Standard Middleware missing & bad token
		mw := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		recMW1 := httptest.NewRecorder()
		mw.ServeHTTP(recMW1, reqNoAuth)
		if recMW1.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 from Middleware on missing auth, got %d", recMW1.Code)
		}

		recMW2 := httptest.NewRecorder()
		mw.ServeHTTP(recMW2, reqBadTok)
		if recMW2.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 from Middleware on bad token, got %d", recMW2.Code)
		}

		// ClaimsFromContext with empty context
		if c, ok := ClaimsFromContext(context.Background()); ok || c != nil {
			t.Fatal("expected ClaimsFromContext to return nil, false on empty context")
		}
	})

	// --- 3. ClaimsLarge Getters & parseLargeClaims ---
	t.Run("ClaimsLargeCoverage", func(t *testing.T) {
		var cl ClaimsLarge
		cl.subBuf[0] = 's'
		cl.subLen = 1
		cl.userBuf[0] = 'u'
		cl.userLen = 1
		cl.issBuf[0] = 'i'
		cl.issLen = 1
		cl.audBuf[0] = 'a'
		cl.audLen = 1
		cl.jtiBuf[0] = 'j'
		cl.jtiLen = 1

		if string(cl.Subject()) != "s" || string(cl.Username()) != "u" ||
			string(cl.Issuer()) != "i" || string(cl.Audience()) != "a" || string(cl.JTI()) != "j" {
			t.Fatal("ClaimsLarge getters mismatch")
		}

		// Test parseLargeClaims edge cases
		var outLarge ClaimsLarge

		// Bad JSON
		if err := v.parseLargeClaims([]byte("not_json"), now, &outLarge); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload, got %v", err)
		}

		// exp as string
		if err := v.parseLargeClaims([]byte(`{"sub":"1","exp":"string"}`), now, &outLarge); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for exp as string, got %v", err)
		}
		// exp invalid number
		if err := v.parseLargeClaims([]byte(`{"sub":"1","exp":123abc}`), now, &outLarge); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for invalid exp number, got %v", err)
		}
		// expired
		if err := v.parseLargeClaims([]byte(`{"sub":"1","exp":100}`), now, &outLarge); !errors.Is(err, ErrExpiredToken) {
			t.Fatalf("expected ErrExpiredToken, got %v", err)
		}

		// nbf as string
		if err := v.parseLargeClaims([]byte(`{"sub":"1","nbf":"string"}`), now, &outLarge); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for nbf as string, got %v", err)
		}
		// nbf invalid number
		if err := v.parseLargeClaims([]byte(`{"sub":"1","nbf":123abc}`), now, &outLarge); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for invalid nbf number, got %v", err)
		}
		// nbf not valid yet
		if err := v.parseLargeClaims([]byte(`{"sub":"1","nbf":9999999999}`), now, &outLarge); !errors.Is(err, ErrNotValidYet) {
			t.Fatalf("expected ErrNotValidYet, got %v", err)
		}

		// iat as string & invalid number
		if err := v.parseLargeClaims([]byte(`{"sub":"1","iat":"str"}`), now, &outLarge); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for iat string, got %v", err)
		}
		if err := v.parseLargeClaims([]byte(`{"sub":"1","iat":123abc}`), now, &outLarge); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for iat invalid, got %v", err)
		}

		// sub empty, sub non-string, sub > 256
		if err := v.parseLargeClaims([]byte(`{"sub":""}`), now, &outLarge); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for empty sub, got %v", err)
		}
		if err := v.parseLargeClaims([]byte(`{"sub":123}`), now, &outLarge); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for numeric sub, got %v", err)
		}
		oversizedSub := bytes.Repeat([]byte("a"), 257)
		if err := v.parseLargeClaims(append(append([]byte(`{"sub":"`), oversizedSub...), []byte(`"}`)...), now, &outLarge); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for sub > 256, got %v", err)
		}

		// username non-string & username > 256
		if err := v.parseLargeClaims([]byte(`{"sub":"1","username":123}`), now, &outLarge); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for numeric username, got %v", err)
		}
		oversizedUser := bytes.Repeat([]byte("u"), 257)
		if err := v.parseLargeClaims(append(append([]byte(`{"sub":"1","username":"`), oversizedUser...), []byte(`"}`)...), now, &outLarge); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for username > 256, got %v", err)
		}

		// iss non-string & iss mismatch & iss > 256
		if err := v.parseLargeClaims([]byte(`{"sub":"1","iss":123}`), now, &outLarge); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for numeric iss, got %v", err)
		}
		if err := v.parseLargeClaims([]byte(`{"sub":"1","iss":"wrong.iss"}`), now, &outLarge); !errors.Is(err, ErrInvalidIssuer) {
			t.Fatalf("expected ErrInvalidIssuer, got %v", err)
		}
		oversizedIss := bytes.Repeat([]byte("i"), 257)
		if err := v.parseLargeClaims(append(append([]byte(`{"sub":"1","iss":"`), oversizedIss...), []byte(`"}`)...), now, &outLarge); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for iss > 256, got %v", err)
		}

		// aud mismatch & aud non-string & aud > 256
		if err := v.parseLargeClaims([]byte(`{"sub":"1","iss":"auth.test","aud":"wrong.aud"}`), now, &outLarge); !errors.Is(err, ErrInvalidAudience) {
			t.Fatalf("expected ErrInvalidAudience for wrong aud string, got %v", err)
		}
		oversizedAud := bytes.Repeat([]byte("a"), 257)
		vNoAud := NewVerifier(secret)
		if err := vNoAud.parseLargeClaims(append(append([]byte(`{"sub":"1","aud":"`), oversizedAud...), []byte(`"}`)...), now, &outLarge); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for aud > 256, got %v", err)
		}

		// jti non-string & jti > 256
		if err := v.parseLargeClaims([]byte(`{"sub":"1","jti":123}`), now, &outLarge); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for numeric jti, got %v", err)
		}
		oversizedJti := bytes.Repeat([]byte("j"), 257)
		if err := v.parseLargeClaims(append(append([]byte(`{"sub":"1","jti":"`), oversizedJti...), []byte(`"}`)...), now, &outLarge); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for jti > 256, got %v", err)
		}

		// missing required sub
		if err := v.parseLargeClaims([]byte(`{"iss":"auth.test","aud":"api.test"}`), now, &outLarge); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for missing sub, got %v", err)
		}

		// parseStandardClaims missing required iss or aud
		var stdClaims Claims
		if err := v.parseStandardClaims([]byte(`{"sub":"1","aud":"api.test"}`), now, &stdClaims); !errors.Is(err, ErrInvalidIssuer) {
			t.Fatalf("expected ErrInvalidIssuer for missing iss, got %v", err)
		}
		if err := v.parseStandardClaims([]byte(`{"sub":"1","iss":"auth.test"}`), now, &stdClaims); !errors.Is(err, ErrInvalidAudience) {
			t.Fatalf("expected ErrInvalidAudience for missing aud, got %v", err)
		}
	})

	// --- 4. VerifyCustom Edge Cases ---
	t.Run("VerifyCustomEdgeCases", func(t *testing.T) {
		validTok := v.SignClaims(nil, []byte("1"), []byte("alice"), now, now+3600)

		// Tampered / bad token payload
		badTok := []byte("eyJhbGciOiJIUzI1NiJ9.bm90LWpzb24.sig")
		if err := v.VerifyCustom(badTok, now, nil); err == nil {
			t.Fatal("expected error for non-json payload in VerifyCustom")
		}

		// exp as string in VerifyCustom
		expStrTok := v.Sign(nil, []byte(`{"sub":"1","exp":"tomorrow"}`))
		if err := v.VerifyCustom(expStrTok, now, nil); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for exp as string, got %v", err)
		}
		// exp invalid numeric
		expBadNum := v.Sign(nil, []byte(`{"sub":"1","exp":123xyz}`))
		if err := v.VerifyCustom(expBadNum, now, nil); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for invalid exp, got %v", err)
		}
		// exp expired
		expExpired := v.Sign(nil, []byte(`{"sub":"1","exp":100}`))
		if err := v.VerifyCustom(expExpired, now, nil); !errors.Is(err, ErrExpiredToken) {
			t.Fatalf("expected ErrExpiredToken, got %v", err)
		}

		// nbf as string
		nbfStr := v.Sign(nil, []byte(`{"sub":"1","nbf":"soon"}`))
		if err := v.VerifyCustom(nbfStr, now, nil); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for nbf string, got %v", err)
		}
		// nbf invalid numeric
		nbfBadNum := v.Sign(nil, []byte(`{"sub":"1","nbf":123xyz}`))
		if err := v.VerifyCustom(nbfBadNum, now, nil); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for invalid nbf, got %v", err)
		}
		// nbf not valid yet
		nbfFuture := v.Sign(nil, []byte(`{"sub":"1","nbf":9999999999}`))
		if err := v.VerifyCustom(nbfFuture, now, nil); !errors.Is(err, ErrNotValidYet) {
			t.Fatalf("expected ErrNotValidYet, got %v", err)
		}

		// iss mismatch in VerifyCustom
		badIssTok := v.Sign(nil, []byte(`{"sub":"1","iss":"bad.iss","aud":"api.test"}`))
		if err := v.VerifyCustom(badIssTok, now, nil); !errors.Is(err, ErrInvalidIssuer) {
			t.Fatalf("expected ErrInvalidIssuer in VerifyCustom, got %v", err)
		}

		// aud mismatch in VerifyCustom
		badAudTok := v.Sign(nil, []byte(`{"sub":"1","iss":"auth.test","aud":"bad.aud"}`))
		if err := v.VerifyCustom(badAudTok, now, nil); !errors.Is(err, ErrInvalidAudience) {
			t.Fatalf("expected ErrInvalidAudience in VerifyCustom, got %v", err)
		}

		// missing required iss or aud in VerifyCustom
		noIssTok := v.Sign(nil, []byte(`{"sub":"1","aud":"api.test"}`))
		if err := v.VerifyCustom(noIssTok, now, nil); !errors.Is(err, ErrInvalidIssuer) {
			t.Fatalf("expected ErrInvalidIssuer when iss missing in VerifyCustom, got %v", err)
		}
		noAudTok := v.Sign(nil, []byte(`{"sub":"1","iss":"auth.test"}`))
		if err := v.VerifyCustom(noAudTok, now, nil); !errors.Is(err, ErrInvalidAudience) {
			t.Fatalf("expected ErrInvalidAudience when aud missing in VerifyCustom, got %v", err)
		}

		// Valid VerifyCustom
		if err := v.VerifyCustom(validTok, now, nil); err != nil {
			t.Fatalf("expected valid token in VerifyCustom, got %v", err)
		}
	})

	// --- 5. ECDSA DER Conversion Edge Cases ---
	t.Run("ECDSADEREdgeCases", func(t *testing.T) {
		var derBuf [72]byte

		// encodeP1363ToDER with empty r or s
		if _, ok := encodeP1363ToDER(&derBuf, nil, []byte("s")); ok {
			t.Fatal("expected failure on empty r")
		}
		if _, ok := encodeP1363ToDER(&derBuf, []byte("r"), nil); ok {
			t.Fatal("expected failure on empty s")
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
	})

	// --- 6. Scanner Edge Cases (ParseNumeric, ParsePositiveInt, Unescape, NextJSONProp) ---
	t.Run("ScannerEdgeCases", func(t *testing.T) {
		// ParseNumeric
		if _, ok := ParseNumeric(nil); ok {
			t.Fatal("expected false on nil ParseNumeric")
		}
		if num, ok := ParseNumeric([]byte("-42.5")); !ok || num != -42.5 {
			t.Fatalf("expected -42.5, got %v (ok=%v)", num, ok)
		}
		if num, ok := ParseNumeric([]byte("1e-2")); !ok || num != 0.01 {
			t.Fatalf("expected 0.01, got %v (ok=%v)", num, ok)
		}
		if num, ok := ParseNumeric([]byte("2.5E+2")); !ok || num != 250.0 {
			t.Fatalf("expected 250.0, got %v (ok=%v)", num, ok)
		}
		if _, ok := ParseNumeric([]byte("42.")); ok {
			t.Fatal("expected false for incomplete fraction 42.")
		}
		if _, ok := ParseNumeric([]byte("42e")); ok {
			t.Fatal("expected false for incomplete exponent 42e")
		}
		if _, ok := ParseNumeric([]byte("42abc")); ok {
			t.Fatal("expected false for invalid trailing chars")
		}
		if _, ok := ParseNumeric([]byte("abc")); ok {
			t.Fatal("expected false for non-numeric string")
		}

		// ParsePositiveInt
		if _, ok := ParsePositiveInt(nil); ok {
			t.Fatal("expected false for nil ParsePositiveInt")
		}
		if _, ok := ParsePositiveInt(bytes.Repeat([]byte("1"), 19)); ok {
			t.Fatal("expected false for len > 18")
		}
		if _, ok := ParsePositiveInt([]byte("12a")); ok {
			t.Fatal("expected false for non-digits")
		}
		if _, ok := ParsePositiveInt([]byte("0")); ok {
			t.Fatal("expected false for 0")
		}

		// TrimJSONArray
		if _, ok := TrimJSONArray([]byte("not_array")); ok {
			t.Fatal("expected false for TrimJSONArray non-array")
		}
		if _, ok := TrimJSONArray([]byte("{ }")); ok {
			t.Fatal("expected false for TrimJSONArray object")
		}
		if _, ok := TrimJSONArray([]byte("")); ok {
			t.Fatal("expected false for TrimJSONArray empty")
		}

		// NextArrayElement
		if _, _, _, ok := NextArrayElement([]byte("")); ok {
			t.Fatal("expected false for empty array element")
		}
		if _, _, _, ok := NextArrayElement([]byte("   ")); ok {
			t.Fatal("expected false for whitespace array element")
		}

		// UnescapeJSONInPlace
		escapedSlash := []byte(`a\/b\b\f\r\t\u0020\x`)
		unescaped := UnescapeJSONInPlace(escapedSlash)
		if !bytes.Contains(unescaped, []byte("/")) || !bytes.Contains(unescaped, []byte("\b")) {
			t.Fatalf("unexpected unescaped result: %q", unescaped)
		}
		// Invalid hex in \u
		invalidHex := []byte(`\u00ZZ`)
		unescInv := UnescapeJSONInPlace(invalidHex)
		if string(unescInv) != `u00ZZ` {
			t.Fatalf("expected u00ZZ, got %s", unescInv)
		}
		// Trailing backslash
		trailingSlash := []byte(`abc\`)
		unescTrailing := UnescapeJSONInPlace(trailingSlash)
		if string(unescTrailing) != `abc\` {
			t.Fatalf("expected abc\\, got %s", unescTrailing)
		}

		// NextJSONProp edge cases
		if _, _, _, _, ok := NextJSONProp([]byte(`key:123`)); ok {
			t.Fatal("expected false for unquoted key in NextJSONProp")
		}
		if _, _, _, _, ok := NextJSONProp([]byte(`"key" 123`)); ok {
			t.Fatal("expected false for missing colon in NextJSONProp")
		}
		if _, _, _, _, ok := NextJSONProp([]byte(`"key":`)); ok {
			t.Fatal("expected false for missing value after colon")
		}
		if _, _, _, _, ok := NextJSONProp([]byte(`"unclosed_key`)); ok {
			t.Fatal("expected false for unclosed string key")
		}
		if _, _, _, _, ok := NextJSONProp([]byte(`"key":"unclosed_val`)); ok {
			t.Fatal("expected false for unclosed string val")
		}
		if _, _, _, _, ok := NextJSONProp([]byte(`"key":{"unclosed_obj`)); ok {
			t.Fatal("expected false for unclosed nested object")
		}
		if _, _, _, _, ok := NextJSONProp([]byte(`"key":["unclosed_arr`)); ok {
			t.Fatal("expected false for unclosed nested array")
		}
	})

	// --- 7. SignWithScratch & Destroy ---
	t.Run("SignWithScratchAndDestroy", func(t *testing.T) {
		res := v.SignWithScratch(nil, []byte(`{"sub":"123"}`), st)
		if len(res) == 0 {
			t.Fatal("expected non-empty token from SignWithScratch")
		}
		vDestroy := NewVerifierWithOptions([]byte("key1"), Options{
			Keys: []Key{{ID: "k1", Secret: []byte("s1")}},
		})
		vDestroy.Destroy()
	})

	// --- 8. Complete 100% Edge Coverage ---
	t.Run("RemainingEdgeCases", func(t *testing.T) {
		// 8.1 VerifyLargeWithScratch with invalid token
		var cl ClaimsLarge
		if err := v.VerifyLargeWithScratch([]byte("invalid.token.here"), now, &cl, st); err == nil {
			t.Fatal("expected error from VerifyLargeWithScratch with invalid token")
		}

		// 8.2 VerifyCustom edge cases (TrimJSONObject fail, NextJSONProp fail)
		tokArray := v.Sign(nil, []byte(`[1, 2, 3]`))
		if err := v.VerifyCustom(tokArray, now, func(k, val []byte, isStr bool) bool { return true }); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for array in VerifyCustom, got %v", err)
		}
		tokMalCustom := v.Sign(nil, []byte(`{"sub":"u", "bad": }`))
		if err := v.VerifyCustom(tokMalCustom, now, func(k, val []byte, isStr bool) bool { return true }); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for malformed in VerifyCustom, got %v", err)
		}

		// 8.3 Nil private keys in Sign
		ecPrivTmp, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		vESPubOnly := NewES256Verifier(&ecPrivTmp.PublicKey, nil, Options{})
		tokESNoPriv := vESPubOnly.Sign(nil, []byte(`{"sub":"123"}`))
		if len(tokESNoPriv) == 0 {
			t.Fatal("expected token output even with nil ecPriv")
		}

		edPubTmp, _, _ := ed25519.GenerateKey(rand.Reader)
		vEdPubOnly := NewEd25519Verifier(edPubTmp, nil, Options{})
		tokEdNoPriv := vEdPubOnly.Sign(nil, []byte(`{"sub":"123"}`))
		if len(tokEdNoPriv) == 0 {
			t.Fatal("expected token output even with nil edPriv")
		}

		// 8.4 Header validation edge cases
		// Oversized header (>128 bytes decoded)
		bigHdr := base64.RawURLEncoding.EncodeToString(make([]byte, 200))
		tokBigHdr := []byte(bigHdr + ".e30.c2ln")
		if err := v.Verify(tokBigHdr, now, &Claims{}); !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("expected ErrInvalidHeader for oversized header, got %v", err)
		}

		// Oversized signature (>64 bytes decoded)
		bigSig := base64.RawURLEncoding.EncodeToString(make([]byte, 100))
		tokBigSig := []byte("eyJhbGciOiJIUzI1NiJ9.e30." + bigSig)
		if err := v.Verify(tokBigSig, now, &Claims{}); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("expected ErrInvalidSignature for oversized sig, got %v", err)
		}

		// kid empty string
		hdrEmptyKid := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":""}`))
		tokKid1 := []byte(hdrEmptyKid + ".eyJzdWIiOiIxMjMifQ.c2ln")
		if err := v.Verify(tokKid1, now, &Claims{}); !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("expected ErrInvalidHeader for empty kid, got %v", err)
		}

		// kid non-string
		hdrNonStrKid := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":123}`))
		tokKid2 := []byte(hdrNonStrKid + ".eyJzdWIiOiIxMjMifQ.c2ln")
		if err := v.Verify(tokKid2, now, &Claims{}); !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("expected ErrInvalidHeader for non-string kid, got %v", err)
		}

		// Missing alg header
		hdrNoAlg := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT"}`))
		tokNoAlg := []byte(hdrNoAlg + ".eyJzdWIiOiIxMjMifQ.c2ln")
		if err := v.Verify(tokNoAlg, now, &Claims{}); !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("expected ErrInvalidHeader for missing alg, got %v", err)
		}

		// Malformed header JSON
		hdrMalformed := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256", "bad": }`))
		tokHdrMal := []byte(hdrMalformed + ".eyJzdWIiOiIxMjMifQ.c2ln")
		if err := v.Verify(tokHdrMal, now, &Claims{}); !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("expected ErrInvalidHeader for malformed header, got %v", err)
		}

		// 8.5 ES256 and EdDSA key rotation with kid
		ecPrivRot, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		vESRot := NewVerifierWithOptions(nil, Options{
			Algorithm: AlgES256,
			Keys:      []Key{{ID: "es-k1", ECDSAPublic: &ecPrivRot.PublicKey}},
		})
		vESRotSigner := NewES256Verifier(&ecPrivRot.PublicKey, ecPrivRot, Options{
			ActiveKeyID: "es-k1",
		})
		tokESRot := vESRotSigner.Sign(nil, []byte(`{"sub":"rot1"}`))
		var clES Claims
		if err := vESRot.Verify(tokESRot, now, &clES); err != nil {
			t.Fatalf("expected ES256 key rotation verify to succeed, got %v", err)
		}

		edPubRot, edPrivRot, _ := ed25519.GenerateKey(rand.Reader)
		vEdRot := NewVerifierWithOptions(nil, Options{
			Algorithm: AlgEdDSA,
			Keys:      []Key{{ID: "ed-k1", Ed25519Public: edPubRot}},
		})
		vEdRotSigner := NewEd25519Verifier(edPubRot, edPrivRot, Options{
			ActiveKeyID: "ed-k1",
		})
		tokEdRot := vEdRotSigner.Sign(nil, []byte(`{"sub":"rot2"}`))
		var clEd Claims
		if err := vEdRot.Verify(tokEdRot, now, &clEd); err != nil {
			t.Fatalf("expected EdDSA key rotation verify to succeed, got %v", err)
		}

		// ES256 verification with nil pub key
		vESNilPub := NewES256Verifier(nil, nil, Options{})
		if err := vESNilPub.Verify(tokESRot, now, &clES); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("expected ErrInvalidSignature when pub == nil, got %v", err)
		}

		// ES256 verification when encodeP1363ToDER returns false (all-zero signature)
		zeroSig := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
		parts := bytes.Split(tokESRot, []byte("."))
		tokZeroSig := append(append(append([]byte(nil), parts[0]...), '.'), append(append(parts[1], '.'), []byte(zeroSig)...)...)
		if err := vESRot.Verify(tokZeroSig, now, &clES); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("expected ErrInvalidSignature for all-zero ES256 sig, got %v", err)
		}

		// Invalid base64 in payload with valid signature
		badB64Input := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.!!!not-base64!!!"
		macBadB64 := hmac.New(sha256.New, secret)
		macBadB64.Write([]byte(badB64Input))
		sigBadB64 := base64.RawURLEncoding.EncodeToString(macBadB64.Sum(nil))
		tokBadB64 := []byte(badB64Input + "." + sigBadB64)
		if err := v.Verify(tokBadB64, now, &Claims{}); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for invalid base64 payload, got %v", err)
		}

		// 8.6 parseStandardClaims branches
		// Array payload
		if err := v.Verify(tokArray, now, &Claims{}); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for array payload in Verify, got %v", err)
		}
		// Malformed payload
		if err := v.Verify(tokMalCustom, now, &Claims{}); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for malformed payload in Verify, got %v", err)
		}
		// exp as string
		tokExpStr := v.Sign(nil, []byte(`{"sub":"u","exp":"123"}`))
		if err := v.Verify(tokExpStr, now, &Claims{}); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for exp as string, got %v", err)
		}
		// exp invalid numeric
		tokExpBad := v.Sign(nil, []byte(`{"sub":"u","exp":12.34.56}`))
		if err := v.Verify(tokExpBad, now, &Claims{}); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for exp bad numeric, got %v", err)
		}
		// nbf as string
		tokNbfStr := v.Sign(nil, []byte(`{"sub":"u","nbf":"123"}`))
		if err := v.Verify(tokNbfStr, now, &Claims{}); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for nbf as string, got %v", err)
		}
		// nbf invalid numeric
		tokNbfBad := v.Sign(nil, []byte(`{"sub":"u","nbf":12.34.56}`))
		if err := v.Verify(tokNbfBad, now, &Claims{}); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for nbf bad numeric, got %v", err)
		}
		// iat as string
		tokIatStr := v.Sign(nil, []byte(`{"sub":"u","iat":"123"}`))
		if err := v.Verify(tokIatStr, now, &Claims{}); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for iat as string, got %v", err)
		}
		// iat invalid numeric
		tokIatBad := v.Sign(nil, []byte(`{"sub":"u","iat":12.34.56}`))
		if err := v.Verify(tokIatBad, now, &Claims{}); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for iat bad numeric, got %v", err)
		}
		// iss not string
		tokIssNum := v.Sign(nil, []byte(`{"sub":"u","iss":123}`))
		if err := v.Verify(tokIssNum, now, &Claims{}); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for iss not string, got %v", err)
		}
		// iss too long (>64 bytes)
		long65 := string(make([]byte, 65))
		tokIssLong := v.Sign(nil, []byte(`{"sub":"u","iss":"` + long65 + `"}`))
		if err := v.Verify(tokIssLong, now, &Claims{}); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for iss over 64 bytes, got %v", err)
		}
		// aud array mismatch
		tokAudArrMismatch := v.Sign(nil, []byte(`{"sub":"u","aud":["other1","other2"]}`))
		if err := v.Verify(tokAudArrMismatch, now, &Claims{}); !errors.Is(err, ErrInvalidAudience) {
			t.Fatalf("expected ErrInvalidAudience for aud array mismatch, got %v", err)
		}
		// aud numeric
		vNoAud := NewVerifier(secret)
		tokAudNum := vNoAud.Sign(nil, []byte(`{"sub":"u","aud":123}`))
		if err := vNoAud.Verify(tokAudNum, now, &Claims{}); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for aud numeric, got %v", err)
		}
		// aud > 64 bytes
		tokAudLong := vNoAud.Sign(nil, []byte(`{"sub":"u","aud":"` + long65 + `"}`))
		if err := vNoAud.Verify(tokAudLong, now, &Claims{}); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for aud > 64 bytes, got %v", err)
		}
		// jti not string
		tokJtiNum := v.Sign(nil, []byte(`{"sub":"u","jti":123}`))
		if err := v.Verify(tokJtiNum, now, &Claims{}); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for jti not string, got %v", err)
		}

		// 8.7 parseLargeClaims branches
		tokMalPlLarge := v.Sign(nil, []byte(`{"sub":"u", "bad": }`))
		var clLarge ClaimsLarge
		if err := v.VerifyLarge(tokMalPlLarge, now, &clLarge); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for large malformed payload, got %v", err)
		}
		if err := vNoAud.VerifyLarge(tokAudNum, now, &clLarge); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for large numeric aud, got %v", err)
		}
		tokJtiLarge := v.Sign(nil, []byte(`{"sub":"u","iss":"auth.test","aud":"api.test","jti":"custom-jti-1234"}`))
		if err := v.VerifyLarge(tokJtiLarge, now, &clLarge); err != nil {
			t.Fatalf("expected VerifyLarge with jti to succeed, got %v", err)
		}
		if string(clLarge.JTI()) != "custom-jti-1234" {
			t.Fatalf("expected custom-jti-1234, got %s", clLarge.JTI())
		}
		tokNoIss := v.Sign(nil, []byte(`{"sub":"u","aud":"api.test"}`))
		if err := v.VerifyLarge(tokNoIss, now, &clLarge); !errors.Is(err, ErrInvalidIssuer) {
			t.Fatalf("expected ErrInvalidIssuer for missing iss on large, got %v", err)
		}
		tokNoAud := v.Sign(nil, []byte(`{"sub":"u","iss":"auth.test"}`))
		if err := v.VerifyLarge(tokNoAud, now, &clLarge); !errors.Is(err, ErrInvalidAudience) {
			t.Fatalf("expected ErrInvalidAudience for missing aud on large, got %v", err)
		}

		// 8.8 matchAudienceClaim edge cases
		tokAudEmptyArr := vNoAud.Sign(nil, []byte(`{"sub":"u","aud":[]}`))
		if err := vNoAud.Verify(tokAudEmptyArr, now, &Claims{}); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for empty aud array, got %v", err)
		}
		tokAudNonStrArr := vNoAud.Sign(nil, []byte(`{"sub":"u","aud":["api.test", 123]}`))
		if err := vNoAud.Verify(tokAudNonStrArr, now, &Claims{}); !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload for aud array with non-string, got %v", err)
		}

		// 8.9 DER helpers
		var derBuf [72]byte
		encodeP1363ToDER(&derBuf, []byte{0, 1, 2}, []byte{0, 3, 4})
		var p1363Buf [64]byte
		derLong := []byte{0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}
		decodeDERToP1363(derLong, p1363Buf[:])

		// 8.10 Scanner edge cases
		if _, _, _, _, ok := NextJSONProp([]byte("  ,  ")); ok {
			t.Fatal("expected false for whitespace/commas in NextJSONProp")
		}
		if _, _, _, ok := NextArrayElement([]byte("\"unclosed")); ok {
			t.Fatal("expected false for unclosed string in NextArrayElement")
		}
		if _, val, _, _, ok := NextJSONProp([]byte(`"key":["str\"ing"]`)); !ok || len(val) == 0 {
			t.Fatal("expected ok for nested string with escape")
		}
		if _, val, _, _, ok := NextJSONProp([]byte(`"key":[[1, 2]]`)); !ok || len(val) == 0 {
			t.Fatal("expected ok for nested array")
		}
		if _, _, _, _, ok := NextJSONProp([]byte(`"key":,`)); ok {
			t.Fatal("expected false for immediate delimiter")
		}
		unescN := UnescapeJSONInPlace([]byte("line1\\nline2"))
		if !bytes.Contains(unescN, []byte("\n")) {
			t.Fatal("expected newline in unescaped result")
		}
	})
}
