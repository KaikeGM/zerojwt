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
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestVerifyAndSign(t *testing.T) {
	secret := []byte("twelve-dollar-challenge")
	v := NewVerifier(secret)
	now := time.Now().Unix()

	// 1. SignClaims & Verify roundtrip (valid token)
	var tokBuf [512]byte
	validTok := v.SignClaims(tokBuf[:0], []byte("123"), []byte("alice"), now, now+3600)

	var claims Claims
	if err := v.Verify(validTok, now, &claims); err != nil {
		t.Fatalf("expected valid token, got err=%v", err)
	}
	if claims.SubjectID != 123 || string(claims.Subject()) != "123" || string(claims.Username()) != "alice" {
		t.Fatalf("unexpected claims: id=%d sub=%s user=%s", claims.SubjectID, claims.Subject(), claims.Username())
	}

	// 2. VerifyBearer helper
	bearerHdr := append([]byte("Bearer "), validTok...)
	if err := v.VerifyBearer(bearerHdr, now, &claims); err != nil {
		t.Fatalf("expected VerifyBearer to succeed, got %v", err)
	}
	if err := v.VerifyBearer(validTok, now, &claims); !errors.Is(err, ErrMissingBearer) {
		t.Fatalf("expected ErrMissingBearer, got %v", err)
	}

	// 3. Expired token (standard)
	expTok := v.SignClaims(nil, []byte("123"), []byte("alice"), now-7200, now-3600)
	if err := v.Verify(expTok, now, &claims); !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("expected ErrExpiredToken, got %v", err)
	}

	// 4. Expired token with username before exp (key order independence)
	expBeforeTok := v.SignHS256(nil, []byte(fmt.Sprintf(`{"username":"expert","exp":%d,"sub":"123"}`, now-3600)))
	if err := v.Verify(expBeforeTok, now, &claims); !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("expected ErrExpiredToken when username precedes exp, got %v", err)
	}

	// 5. Token with 'exp' substring inside username string
	expInStrTok := v.SignHS256(nil, []byte(fmt.Sprintf(`{"username":"my_exp:100","sub":"123","exp":%d}`, now-3600)))
	if err := v.Verify(expInStrTok, now, &claims); !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("expected ErrExpiredToken when 'exp' is inside username, got %v", err)
	}

	// 6. Token not valid yet (nbf in future)
	nbfTok := v.SignHS256(nil, []byte(fmt.Sprintf(`{"sub":"123","nbf":%d,"exp":%d}`, now+600, now+3600)))
	if err := v.Verify(nbfTok, now, &claims); !errors.Is(err, ErrNotValidYet) {
		t.Fatalf("expected ErrNotValidYet, got %v", err)
	}

	// 7. Non-numeric string sub (e.g., UUID or "user_abc") is valid in general JWT, SubjectID remains 0
	uuidSubTok := v.SignHS256(nil, []byte(fmt.Sprintf(`{"sub":"user_abc","username":"alice","exp":%d}`, now+3600)))
	if err := v.Verify(uuidSubTok, now, &claims); err != nil {
		t.Fatalf("expected non-numeric string sub to pass, got %v", err)
	}
	if string(claims.Subject()) != "user_abc" || claims.SubjectID != 0 {
		t.Fatalf("expected sub=user_abc and SubjectID=0, got sub=%s id=%d", claims.Subject(), claims.SubjectID)
	}

	// 8. Sub is a JSON number instead of string: {"sub":123} -> ErrInvalidPayload (RFC 7519 StringOrURI)
	numSubTok := v.SignHS256(nil, []byte(fmt.Sprintf(`{"sub":123,"username":"alice","exp":%d}`, now+3600)))
	if err := v.Verify(numSubTok, now, &claims); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected numeric sub to return ErrInvalidPayload, got %v", err)
	}

	// 9. Tampered signature
	badSigTok := append([]byte(nil), validTok...)
	badSigTok[len(badSigTok)-2] ^= 0x01
	if err := v.Verify(badSigTok, now, &claims); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}

	// 10. Alg: none attack
	enc := base64.RawURLEncoding
	noneH := enc.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	noneP := enc.EncodeToString([]byte(fmt.Sprintf(`{"sub":"123","username":"alice","exp":%d}`, now+3600)))
	noneTok := []byte(noneH + "." + noneP + ".")
	if err := v.Verify(noneTok, now, &claims); !errors.Is(err, ErrInvalidToken) && !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected alg:none to fail, got %v", err)
	}

	// 11. Escaped quotes and Unicode \u0022 in username & keys
	unicodeTok := v.SignHS256(nil, []byte(fmt.Sprintf(`{"sub":"888","extra\"key":"test","username":"ev\u0022il","exp":%d}`, now+3600)))
	if err := v.Verify(unicodeTok, now, &claims); err != nil {
		t.Fatalf("expected unicode escaped quote token to pass, got %v", err)
	}
	if claims.SubjectID != 888 || string(claims.Username()) != `ev"il` {
		t.Fatalf("expected id=888 user=ev\"il, got id=%d user=%s", claims.SubjectID, claims.Username())
	}

	// 12. VerifyCustom callback for arbitrary claims
	customTok := v.SignHS256(nil, []byte(fmt.Sprintf(`{"sub":"42","role":"admin","tenant":"acme","exp":%d}`, now+3600)))
	var role, tenant string
	err := v.VerifyCustom(customTok, now, func(key, val []byte, isStr bool) bool {
		if bytes.Equal(key, []byte("role")) && isStr {
			role = string(val)
		} else if bytes.Equal(key, []byte("tenant")) && isStr {
			tenant = string(val)
		}
		return true
	})
	if err != nil || role != "admin" || tenant != "acme" {
		t.Fatalf("VerifyCustom failed: err=%v role=%s tenant=%s", err, role, tenant)
	}

	// 13. Formatted JSON with whitespace inside payload and header
	spacesH := enc.EncodeToString([]byte(` { "alg" : "HS256" , "typ" : "JWT" } `))
	spacesP := enc.EncodeToString([]byte(fmt.Sprintf(` { "sub" : "999" , "username" : "bob" , "exp" : %d } `, now+3600)))
	st := v.NewScratch()
	st.mac.Reset()
	_, _ = st.mac.Write([]byte(spacesH))
	_, _ = st.mac.Write(dotByte)
	_, _ = st.mac.Write([]byte(spacesP))
	spacesSig := st.mac.Sum(st.sumBuf[:0])
	spacesTok := fmt.Sprintf("%s.%s.%s", spacesH, spacesP, enc.EncodeToString(spacesSig))
	if err := v.Verify([]byte(spacesTok), now, &claims); err != nil {
		t.Fatalf("expected token with spaces to verify, got %v", err)
	}
	if claims.SubjectID != 999 || string(claims.Username()) != "bob" {
		t.Fatalf("unexpected claims with spaces: id=%d user=%s", claims.SubjectID, claims.Username())
	}

	// 14. Unicode unescaping (accents, multi-byte, surrogate pair emojis)
	unicodeFullTok := v.SignHS256(nil, []byte(fmt.Sprintf(`{"sub":"1","username":"Jos\u00e9_\u4e16\u754c_\uD83D\uDE80","exp":%d}`, now+3600)))
	if err := v.Verify(unicodeFullTok, now, &claims); err != nil {
		t.Fatalf("expected unicode token to verify, got %v", err)
	}
	if string(claims.Username()) != "José_世界_🚀" {
		t.Fatalf("expected username=José_世界_🚀, got %s", claims.Username())
	}

	// 15. Float & scientific notation in timestamps without overflow
	sciTok := v.SignHS256(nil, []byte(`{"sub":"123","iat":1.7e9,"exp":2.5e9}`))
	if err := v.Verify(sciTok, now, &claims); err != nil {
		t.Fatalf("expected scientific notation token to pass, got %v", err)
	}
	if claims.IssuedAt != 1700000000 || claims.ExpiresAt != 2500000000 {
		t.Fatalf("expected iat=1700000000 exp=2500000000, got iat=%d exp=%d", claims.IssuedAt, claims.ExpiresAt)
	}

	// 16. Structural malformed tokens
	malformed := [][]byte{
		[]byte("no-dots"),
		[]byte("one.dot"),
		[]byte("four.dots.in.token"),
		[]byte(".."),
		[]byte(".payload.sig"),
		[]byte("hdr..sig"),
		[]byte("hdr.payload."),
		[]byte("invalid_base64!.payload.sig"),
	}
	for _, m := range malformed {
		if err := v.Verify(m, now, &claims); !errors.Is(err, ErrInvalidToken) && !errors.Is(err, ErrInvalidHeader) && !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("expected error for malformed token %q, got %v", m, err)
		}
	}

	// 17. Size limits: payload too large
	bigPayload := make([]byte, 1025)
	for i := range bigPayload {
		bigPayload[i] = 'a'
	}
	bigTok := v.SignHS256(nil, append(append([]byte(`{"sub":"1","data":"`), bigPayload...), []byte(`"}`)...))
	if err := v.Verify(bigTok, now, &claims); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("expected ErrPayloadTooLarge, got %v", err)
	}

	// 18. Missing sub claim
	noSubTok := v.SignHS256(nil, []byte(fmt.Sprintf(`{"username":"alice","exp":%d}`, now+3600)))
	if err := v.Verify(noSubTok, now, &claims); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for missing sub, got %v", err)
	}

	// 19. Overlong sub (> 64)
	longSub := bytes.Repeat([]byte("s"), 65)
	longSubTok := v.SignHS256(nil, append(append([]byte(`{"sub":"`), longSub...), []byte(`"}`)...))
	if err := v.Verify(longSubTok, now, &claims); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for long sub, got %v", err)
	}

	// 20. Overlong username (> 128)
	longUser := bytes.Repeat([]byte("u"), 129)
	longUserTok := v.SignHS256(nil, append(append([]byte(`{"sub":"1","username":"`), longUser...), []byte(`"}`)...))
	if err := v.Verify(longUserTok, now, &claims); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for long username, got %v", err)
	}

	// 21. VerifyCustom callback cancellation
	if err := v.VerifyCustom(customTok, now, func(key, val []byte, isStr bool) bool {
		return false // reject immediately
	}); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload when onClaim returns false, got %v", err)
	}

	// 22. AppendEscapedJSONString with control characters and escapes
	rawStr := []byte("hello\nworld\r\"test\"\t\x00\x1f\\slash")
	escaped := AppendEscapedJSONString(nil, rawStr)
	expectedEscaped := `"hello\nworld\r\"test\"\t\u0000\u001f\\slash"`
	if string(escaped) != expectedEscaped {
		t.Fatalf("expected escaped string %s, got %s", expectedEscaped, string(escaped))
	}

	// 23. Configurable scratch buffer dimensions via NewVerifierWithOptions (e.g. 4 KB payload)
	vLarge := NewVerifierWithOptions(secret, Options{
		MaxHeaderSize:  256,
		MaxPayloadSize: 4096,
	})
	if err := vLarge.Verify(bigTok, now, &claims); err != nil {
		t.Fatalf("expected 4KB verifier to accept >1KB payload, got %v", err)
	}
	if claims.SubjectID != 1 {
		t.Fatalf("expected SubjectID=1 on large payload, got %d", claims.SubjectID)
	}

	// 24. Header "typ" validation: optional, accepts "JWT"/"jwt", rejects "JWE"
	noTypH := enc.EncodeToString([]byte(`{"alg":"HS256"}`))
	badTypH := enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWE"}`))
	st.mac.Reset()
	_, _ = st.mac.Write([]byte(noTypH))
	_, _ = st.mac.Write(dotByte)
	_, _ = st.mac.Write([]byte(spacesP))
	noTypTok := fmt.Sprintf("%s.%s.%s", noTypH, spacesP, enc.EncodeToString(st.mac.Sum(st.sumBuf[:0])))
	if err := v.Verify([]byte(noTypTok), now, &claims); err != nil {
		t.Fatalf("expected header without optional typ to pass, got %v", err)
	}

	st.mac.Reset()
	_, _ = st.mac.Write([]byte(badTypH))
	_, _ = st.mac.Write(dotByte)
	_, _ = st.mac.Write([]byte(spacesP))
	badTypTok := fmt.Sprintf("%s.%s.%s", badTypH, spacesP, enc.EncodeToString(st.mac.Sum(st.sumBuf[:0])))
	if err := v.Verify([]byte(badTypTok), now, &claims); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for typ=JWE, got %v", err)
	}
}

func TestZeroAllocations(t *testing.T) {
	if raceDetectorEnabled {
		t.Skip("skipping zero-allocations verification under race detector (-race instruments memory and adds runtime allocations)")
	}
	v := NewVerifier([]byte("twelve-dollar-challenge"))
	now := time.Now().Unix()
	tok := v.SignClaims(nil, []byte("12345"), []byte("golden_ember_1"), now, now+3600)
	var claims Claims
	var dst [512]byte

	verifyAllocs := testing.AllocsPerRun(1000, func() {
		if err := v.Verify(tok, now, &claims); err != nil {
			t.Fatal(err)
		}
	})
	if verifyAllocs != 0 {
		t.Fatalf("expected 0 allocs/op in Verify, got %v", verifyAllocs)
	}

	signAllocs := testing.AllocsPerRun(1000, func() {
		_ = v.SignClaims(dst[:0], []byte("12345"), []byte("golden_ember_1"), now, now+3600)
	})
	if signAllocs != 0 {
		t.Fatalf("expected 0 allocs/op in SignClaims, got %v", signAllocs)
	}

	builderAllocs := testing.AllocsPerRun(1000, func() {
		b := v.NewSigner(dst[:0])
		b.SetSubject([]byte("12345"))
		b.SetClaimInt("tenant_id", 42)
		b.SetClaimString("role", "admin")
		b.SetExpiresAt(now + 3600)
		if _, err := b.Sign(); err != nil {
			t.Fatal(err)
		}
	})
	if builderAllocs != 0 {
		t.Fatalf("expected 0 allocs/op in SignBuilder, got %v", builderAllocs)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	vEd := NewEd25519Verifier(pub, priv, Options{})
	edTok := vEd.SignClaims(nil, []byte("12345"), []byte("alice"), now, now+3600)
	edVerifyAllocs := testing.AllocsPerRun(1000, func() {
		if err := vEd.Verify(edTok, now, &claims); err != nil {
			t.Fatal(err)
		}
	})
	if edVerifyAllocs != 0 {
		t.Fatalf("expected 0 allocs/op in Ed25519 Verify, got %v", edVerifyAllocs)
	}
}

func TestIndustrialSuite(t *testing.T) {
	now := time.Now().Unix()
	secret := []byte("industrial-grade-secret-key-2026")
	var claims Claims

	// 1. HS384 and HS512 algorithms
	for _, alg := range []Algorithm{AlgHS384, AlgHS512} {
		v := NewVerifierWithOptions(secret, Options{Algorithm: alg})
		tok := v.SignClaims(nil, []byte("777"), []byte("operator"), now, now+3600)
		if err := v.Verify(tok, now, &claims); err != nil {
			t.Fatalf("%s verify failed: %v", alg, err)
		}
		if claims.SubjectID != 777 || string(claims.Username()) != "operator" {
			t.Fatalf("%s unexpected claims: id=%d user=%s", alg, claims.SubjectID, claims.Username())
		}
	}

	// 2. Ed25519 (EdDSA / RFC 8037) asymmetric signing and verification
	edPub, edPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	vEd := NewEd25519Verifier(edPub, edPriv, Options{})
	edTok := vEd.SignClaims(nil, []byte("42"), []byte("ed_user"), now, now+3600)
	if err := vEd.Verify(edTok, now, &claims); err != nil {
		t.Fatalf("EdDSA verify failed: %v", err)
	}
	if claims.SubjectID != 42 || string(claims.Username()) != "ed_user" {
		t.Fatalf("EdDSA claims mismatch: id=%d user=%s", claims.SubjectID, claims.Username())
	}
	badEdTok := append([]byte(nil), edTok...)
	badEdTok[len(badEdTok)-3] ^= 0x01
	if err := vEd.Verify(badEdTok, now, &claims); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature on tampered EdDSA token, got %v", err)
	}

	// 3. ECDSA P-256 (ES256) signing and verification
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	vES := NewES256Verifier(&ecPriv.PublicKey, ecPriv, Options{})
	esTok := vES.SignClaims(nil, []byte("99"), []byte("ecdsa_user"), now, now+3600)
	if err := vES.Verify(esTok, now, &claims); err != nil {
		t.Fatalf("ES256 verify failed: %v", err)
	}
	if claims.SubjectID != 99 || string(claims.Username()) != "ecdsa_user" {
		t.Fatalf("ES256 claims mismatch: id=%d user=%s", claims.SubjectID, claims.Username())
	}

	// 4. Clock Skew / Leeway tolerance + Issuer (iss) + Audience (aud string & array) + JTI
	vStrict := NewVerifierWithOptions(secret, Options{
		Leeway:           5 * time.Second,
		ExpectedIssuer:   "auth.zerojwt.io",
		ExpectedAudience: "payment-service",
	})
	var tokBuf [512]byte
	sb := vStrict.NewSigner(tokBuf[:0])
	sb.SetSubject([]byte("500")).
		SetIssuer([]byte("auth.zerojwt.io")).
		SetClaimRawJSON("aud", []byte(`["analytics","payment-service","billing"]`)).
		SetJTI([]byte("550e8400-e29b-41d4-a716-446655440000")).
		SetNotBefore(now + 3). // 3s in the future, within 5s leeway
		SetExpiresAt(now - 2)  // expired 2s ago, within 5s leeway
	leewayTok, err := sb.Sign()
	if err != nil {
		t.Fatalf("SignBuilder failed: %v", err)
	}
	if err := vStrict.Verify(leewayTok, now, &claims); err != nil {
		t.Fatalf("expected token within 5s leeway and matching iss/aud array to pass, got %v", err)
	}
	if string(claims.Issuer()) != "auth.zerojwt.io" ||
		string(claims.Audience()) != "payment-service" ||
		string(claims.JTI()) != "550e8400-e29b-41d4-a716-446655440000" {
		t.Fatalf("unexpected iss/aud/jti: iss=%s aud=%s jti=%s", claims.Issuer(), claims.Audience(), claims.JTI())
	}
	// Outside leeway (10s after exp) -> ErrExpiredToken
	if err := vStrict.Verify(leewayTok, now+10, &claims); !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("expected ErrExpiredToken outside leeway, got %v", err)
	}

	// Mismatched issuer & audience
	sbBadIss := vStrict.NewSigner(nil)
	sbBadIss.SetSubject([]byte("500")).SetIssuer([]byte("evil.io")).SetAudience([]byte("payment-service"))
	badIssTok, _ := sbBadIss.Sign()
	if err := vStrict.Verify(badIssTok, now, &claims); !errors.Is(err, ErrInvalidIssuer) {
		t.Fatalf("expected ErrInvalidIssuer, got %v", err)
	}

	sbBadAud := vStrict.NewSigner(nil)
	sbBadAud.SetSubject([]byte("500")).SetIssuer([]byte("auth.zerojwt.io")).SetAudience([]byte("wrong-service"))
	badAudTok, _ := sbBadAud.Sign()
	if err := vStrict.Verify(badAudTok, now, &claims); !errors.Is(err, ErrInvalidAudience) {
		t.Fatalf("expected ErrInvalidAudience, got %v", err)
	}

	// 5. Key Rotation via "kid" header
	vSignerV2 := NewVerifierWithOptions([]byte("secret-v2-2026"), Options{
		ActiveKeyID: "chave-2026-v2",
	})
	vMultiKey := NewVerifierWithOptions([]byte("fallback-secret"), Options{
		Keys: []Key{
			{ID: "chave-2025-v1", Secret: []byte("secret-v1-2025")},
			{ID: "chave-2026-v2", Secret: []byte("secret-v2-2026")},
		},
	})
	kidTok := vSignerV2.SignClaims(nil, []byte("88"), []byte("rotated_user"), now, now+3600)
	if err := vMultiKey.Verify(kidTok, now, &claims); err != nil {
		t.Fatalf("expected kid-rotated token to verify, got %v", err)
	}
	vUnknownKid := NewVerifierWithOptions([]byte("secret-v3"), Options{
		ActiveKeyID: "chave-unknown",
	})
	unknownKidTok := vUnknownKid.SignClaims(nil, []byte("88"), nil, now, now+3600)
	if err := vMultiKey.Verify(unknownKidTok, now, &claims); !errors.Is(err, ErrUnknownKeyID) {
		t.Fatalf("expected ErrUnknownKeyID, got %v", err)
	}

	// 6. Array Traversal via TrimJSONArray & NextArrayElement
	rawRoles := []byte(` [ "admin" , "editor" , "auditor" ] `)
	arrBody, ok := TrimJSONArray(rawRoles)
	if !ok {
		t.Fatal("expected TrimJSONArray to succeed")
	}
	var parsedRoles []string
	for len(arrBody) > 0 {
		elem, isStr, rest, ok := NextArrayElement(arrBody)
		if !ok || !isStr {
			t.Fatalf("unexpected array parse failure on %q", arrBody)
		}
		parsedRoles = append(parsedRoles, string(elem))
		arrBody = rest
	}
	if len(parsedRoles) != 3 || parsedRoles[0] != "admin" || parsedRoles[1] != "editor" || parsedRoles[2] != "auditor" {
		t.Fatalf("unexpected parsedRoles: %v", parsedRoles)
	}

	// 7. ClaimsLarge (256-byte buffers) & Memory Zeroing (FIPS / PCI-DSS)
	vZero := NewVerifierWithOptions(secret, Options{ZeroMemory: true})
	sub200 := bytes.Repeat([]byte("x"), 200)
	largeSubTok := vZero.SignClaims(nil, sub200, []byte("large_user"), now, now+3600)
	var largeClaims ClaimsLarge
	if err := vZero.VerifyLarge(largeSubTok, now, &largeClaims); err != nil {
		t.Fatalf("VerifyLarge failed: %v", err)
	}
	if !bytes.Equal(largeClaims.Subject(), sub200) {
		t.Fatal("ClaimsLarge subject mismatch")
	}
	largeClaims.Clear()
	if len(largeClaims.Subject()) != 0 {
		t.Fatal("expected Clear() to reset ClaimsLarge")
	}

	// 8. Native HTTP Middlewares (ProtectFunc and Middleware)
	validHTTP := vZero.SignClaims(nil, []byte("321"), []byte("web_admin"), now, now+3600)
	req := httptest.NewRequest(http.MethodGet, "/profile", nil)
	req.Header.Set("Authorization", "Bearer "+string(validHTTP))
	rec := httptest.NewRecorder()

	handler := vZero.ProtectFunc(func(w http.ResponseWriter, r *http.Request, c *Claims) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(c.Username())
	})
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "web_admin" {
		t.Fatalf("ProtectFunc failed: status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec2 := httptest.NewRecorder()
	stdHandler := vZero.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := ClaimsFromContext(r.Context())
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(c.Subject())
	}))
	stdHandler.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK || rec2.Body.String() != "321" {
		t.Fatalf("Middleware failed: status=%d body=%s", rec2.Code, rec2.Body.String())
	}
	vZero.Destroy()
}

func TestConcurrentRaceSafety(t *testing.T) {
	v := NewVerifier([]byte("super-secret-concurrent-key"))
	now := time.Now().Unix()

	const workers = 32
	const iterations = 500
	var wg sync.WaitGroup
	wg.Add(workers)

	for w := 0; w < workers; w++ {
		go func(id int) {
			defer wg.Done()
			sub := []byte(fmt.Sprintf("%d", id+1))
			user := []byte(fmt.Sprintf("user_%d", id+1))
			var tokBuf [512]byte
			var claims Claims

			for i := 0; i < iterations; i++ {
				tok := v.SignClaims(tokBuf[:0], sub, user, now, now+3600)
				if err := v.Verify(tok, now, &claims); err != nil {
					t.Errorf("worker %d verify error: %v", id, err)
					return
				}
				if claims.SubjectID != int64(id+1) || !bytes.Equal(claims.Username(), user) {
					t.Errorf("worker %d mismatch: got id=%d user=%s", id, claims.SubjectID, claims.Username())
					return
				}
			}
		}(w)
	}

	wg.Wait()
}

func FuzzVerify(f *testing.F) {
	v := NewVerifier([]byte("fuzz-secret"))
	now := int64(1700000000)
	seedTok := v.SignClaims(nil, []byte("1"), []byte("alice"), now, now+3600)
	f.Add(seedTok)
	f.Add([]byte("invalid.token.string"))
	f.Add([]byte("eyJhbGciOiJIUzI1NiJ9.e30.aaaa"))

	f.Fuzz(func(t *testing.T, data []byte) {
		var claims Claims
		_ = v.Verify(data, now, &claims)
	})
}

func TestAllAlgorithmsMatrix(t *testing.T) {
	now := time.Now().Unix()
	sec256 := []byte("256-bit-symmetric-secret-key-ok!")
	sec384 := []byte("384-bit-symmetric-secret-key-longer-entropy-required-here!!")
	sec512 := []byte("512-bit-symmetric-secret-key-maximum-security-entropy-guaranteed-for-fips-compliance!!")

	edPub, edPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecPub := &ecPriv.PublicKey

	type algCase struct {
		name     string
		alg      Algorithm
		verifier *Verifier
	}

	cases := []algCase{
		{
			name:     "HS256",
			alg:      AlgHS256,
			verifier: NewVerifier(sec256),
		},
		{
			name:     "HS384",
			alg:      AlgHS384,
			verifier: NewVerifierWithOptions(sec384, Options{Algorithm: AlgHS384}),
		},
		{
			name:     "HS512",
			alg:      AlgHS512,
			verifier: NewVerifierWithOptions(sec512, Options{Algorithm: AlgHS512}),
		},
		{
			name:     "EdDSA (Ed25519)",
			alg:      AlgEdDSA,
			verifier: NewEd25519Verifier(edPub, edPriv, Options{}),
		},
		{
			name:     "ES256 (ECDSA P-256)",
			alg:      AlgES256,
			verifier: NewES256Verifier(ecPub, ecPriv, Options{}),
		},
	}

	generatedTokens := make(map[Algorithm][]byte)

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			v := tc.verifier
			var claims Claims

			// A. SignClaims & Verify roundtrip
			var tokBuf [1024]byte
			tok1 := v.SignClaims(tokBuf[:0], []byte("999"), []byte("alice_operator"), now, now+3600)
			generatedTokens[tc.alg] = append([]byte(nil), tok1...)

			if err := v.Verify(tok1, now, &claims); err != nil {
				t.Fatalf("[%s] Verify failed: %v", tc.name, err)
			}
			if claims.SubjectID != 999 || string(claims.Subject()) != "999" || string(claims.Username()) != "alice_operator" {
				t.Fatalf("[%s] Claims mismatch: id=%d sub=%s user=%s", tc.name, claims.SubjectID, claims.Subject(), claims.Username())
			}

			// B. VerifyBearer roundtrip
			bearer := append([]byte("Bearer "), tok1...)
			if err := v.VerifyBearer(bearer, now, &claims); err != nil {
				t.Fatalf("[%s] VerifyBearer failed: %v", tc.name, err)
			}

			// C. Sign (raw JSON) & VerifyWithScratch
			scratch := v.NewScratch()
			rawPayload := []byte(fmt.Sprintf(`{"sub":"admin_root","role":"superuser","exp":%d}`, now+1800))
			tok2 := v.Sign(nil, rawPayload)
			if err := v.VerifyWithScratch(tok2, now, &claims, scratch); err != nil {
				t.Fatalf("[%s] VerifyWithScratch raw token failed: %v", tc.name, err)
			}
			if string(claims.Subject()) != "admin_root" {
				t.Fatalf("[%s] expected sub=admin_root, got %s", tc.name, claims.Subject())
			}

			// D. SignBuilder (fluent custom claims)
			sb := v.NewSigner(nil)
			sb.SetSubject([]byte("42")).
				SetUsername([]byte("builder_user")).
				SetClaimInt("tenant_id", 101).
				SetClaimString("tier", "enterprise").
				SetClaimBool("active", true).
				SetClaimRawJSON("permissions", []byte(`["read","write","admin"]`)).
				SetExpiresAt(now + 7200)
			tok3, err := sb.Sign()
			if err != nil {
				t.Fatalf("[%s] SignBuilder failed: %v", tc.name, err)
			}
			if err := v.Verify(tok3, now, &claims); err != nil {
				t.Fatalf("[%s] Verify SignBuilder token failed: %v", tc.name, err)
			}
			if claims.SubjectID != 42 || string(claims.Username()) != "builder_user" {
				t.Fatalf("[%s] SignBuilder claims mismatch: id=%d user=%s", tc.name, claims.SubjectID, claims.Username())
			}

			// E. VerifyCustom inspecting arbitrary fields
			var tenantID int64
			var tier string
			var active bool
			errCustom := v.VerifyCustom(tok3, now, func(key, val []byte, isStr bool) bool {
				switch string(key) {
				case "tenant_id":
					if n, ok := ParsePositiveInt(val); ok {
						tenantID = n
					}
				case "tier":
					tier = string(val)
				case "active":
					active = bytes.Equal(val, []byte("true"))
				}
				return true
			})
			if errCustom != nil || tenantID != 101 || tier != "enterprise" || !active {
				t.Fatalf("[%s] VerifyCustom inspection mismatch: tenant=%d tier=%s active=%v err=%v", tc.name, tenantID, tier, active, errCustom)
			}

			// F. Tampered Signature Rejection
			badSig := append([]byte(nil), tok1...)
			badSig[len(badSig)-2] ^= 0x01
			if err := v.Verify(badSig, now, &claims); !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("[%s] expected ErrInvalidSignature on modified signature, got %v", tc.name, err)
			}

			// G. Tampered Payload Rejection
			parts := bytes.Split(tok1, dotByte)
			if len(parts) == 3 {
				badPayload := append([]byte(nil), parts[1]...)
				badPayload[0] ^= 0x01 // mutate base64 payload
				tamperedTok := bytes.Join([][]byte{parts[0], badPayload, parts[2]}, dotByte)
				if err := v.Verify(tamperedTok, now, &claims); err == nil {
					t.Fatalf("[%s] expected error on tampered payload, got nil", tc.name)
				}
			}
		})
	}

	// 2. Cross-Algorithm Security: Token generated with algorithm A must fail on verifier configured for algorithm B
	t.Run("CrossAlgorithmRejection", func(t *testing.T) {
		var claims Claims
		for algA, tokA := range generatedTokens {
			for _, tcB := range cases {
				if tcB.alg == algA {
					continue
				}
				err := tcB.verifier.Verify(tokA, now, &claims)
				if !errors.Is(err, ErrInvalidHeader) {
					t.Fatalf("algorithm confusion security violation: verifier %s accepted token with alg %s (got err=%v, expected ErrInvalidHeader)", tcB.name, algA, err)
				}
			}
		}
	})

	// 3. RFC 7515 Appendix A.1 Official HS256 Test Vector
	t.Run("RFC7515_AppendixA1_HS256", func(t *testing.T) {
		// JWK oct key: "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
		rfcSecretB64 := "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
		rfcSecret, err := base64.RawURLEncoding.DecodeString(rfcSecretB64)
		if err != nil {
			t.Fatalf("failed to decode RFC secret: %v", err)
		}
		// JWS compact serialization from RFC 7515 A.1
		rfcToken := []byte("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." +
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
			"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")

		vRFC := NewVerifierWithOptions(rfcSecret, Options{
			Algorithm:      AlgHS256,
			ExpectedIssuer: "joe",
		})
		var iss string
		var isRoot bool
		var exp float64
		// Verify signature and inspect claims at timestamp <= exp (1300819380)
		errVerify := vRFC.VerifyCustom(rfcToken, 1300819000, func(key, val []byte, isStr bool) bool {
			switch string(key) {
			case "iss":
				iss = string(val)
			case "exp":
				exp, _ = ParseNumeric(val)
			case "http://example.com/is_root":
				isRoot = bytes.Equal(val, []byte("true"))
			}
			return true
		})
		if errVerify != nil {
			t.Fatalf("RFC 7515 A.1 vector verification failed: %v", errVerify)
		}
		if iss != "joe" || exp != 1300819380 || !isRoot {
			t.Fatalf("RFC 7515 A.1 claims mismatch: iss=%s exp=%f isRoot=%v", iss, exp, isRoot)
		}
	})

	// 4. Key Rotation across Asymmetric and Symmetric keys
	t.Run("AsymmetricAndSymmetricKeyRotation", func(t *testing.T) {
		edPub2, edPriv2, _ := ed25519.GenerateKey(nil)
		vEdRotated := NewVerifierWithOptions(nil, Options{
			Algorithm: AlgEdDSA,
			Keys: []Key{
				{ID: "ed-key-v1", Ed25519Public: edPub},
				{ID: "ed-key-v2", Ed25519Public: edPub2},
			},
		})
		vSignerEd2 := NewVerifierWithOptions(nil, Options{
			Algorithm:         AlgEdDSA,
			Ed25519PrivateKey: edPriv2,
			ActiveKeyID:       "ed-key-v2",
		})
		tokEd2 := vSignerEd2.SignClaims(nil, []byte("888"), []byte("rot_ed"), now, now+3600)
		var claims Claims
		if err := vEdRotated.Verify(tokEd2, now, &claims); err != nil {
			t.Fatalf("EdDSA key rotation verify failed: %v", err)
		}
		if claims.SubjectID != 888 {
			t.Fatalf("expected sub=888, got %d", claims.SubjectID)
		}
	})
}
