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

func TestRemainingCoverage(t *testing.T) {
	now := time.Now().Unix()
	secret := bytes.Repeat([]byte("s"), 32)
	v, err := New(secret, Options{
		ExpectedIssuer:   "auth.zerojwt.io",
		ExpectedAudience: "api.zerojwt.io",
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. NewEd25519Verifier & NewES256Verifier with Options parameter
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	vEdWithOpt, err := NewEd25519Verifier(edPub, edPriv, Options{ExpectedIssuer: "ed.iss"})
	if err != nil || vEdWithOpt == nil {
		t.Fatalf("NewEd25519Verifier with opts failed: %v", err)
	}
	// EdDSA derive public from private only
	vEdPrivOnly, err := New(nil, Options{Algorithm: AlgEdDSA, Ed25519PrivateKey: edPriv})
	if err != nil || len(vEdPrivOnly.edPub) != ed25519.PublicKeySize {
		t.Fatalf("expected EdDSA to derive public key from private key, got %v", err)
	}

	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	vEcWithOpt, err := NewES256Verifier(&ecPriv.PublicKey, ecPriv, Options{ExpectedIssuer: "ec.iss"})
	if err != nil || vEcWithOpt == nil {
		t.Fatalf("NewES256Verifier with opts failed: %v", err)
	}
	// ES256 derive public from private only
	vEcPrivOnly, err := New(nil, Options{Algorithm: AlgES256, ECDSAPrivateKey: ecPriv})
	if err != nil || vEcPrivOnly.ecPub == nil {
		t.Fatalf("expected ES256 to derive public key from private key, got %v", err)
	}

	// 2. Destroy on EdDSA and Keys
	vEdDestroy, _ := NewEd25519Verifier(edPub, edPriv)
	vEdDestroy.Destroy()
	if vEdDestroy.CanSign() {
		t.Fatal("expected CanSign false after Destroy on EdDSA")
	}

	vKeysDestroy, _ := New(secret, Options{
		Keys: []Key{
			{ID: "k1", Secret: bytes.Repeat([]byte("k"), 32)},
		},
	})
	vKeysDestroy.Destroy()

	// 3. SignClaimsWithScratch claim variations: Issuer, Audience, JTI, NotBefore, IssuedAt
	st := v.NewScratch()
	tokClaimsFull, err := v.SignClaimsWithScratch(nil, StandardClaims{
		Subject:   "full-sub",
		Username:  "user",
		Issuer:    "auth.zerojwt.io",
		Audience:  "api.zerojwt.io",
		JTI:       "custom-jti",
		IssuedAt:  now,
		NotBefore: now - 5,
		ExpiresAt: now + 3600,
	}, st)
	if err != nil {
		t.Fatalf("SignClaimsWithScratch full failed: %v", err)
	}
	var clFull Claims
	if err := v.Verify(tokClaimsFull, now, &clFull); err != nil {
		t.Fatalf("Verify full claims failed: %v", err)
	}
	if string(clFull.JTI()) != "custom-jti" || clFull.NotBefore != now-5 {
		t.Fatalf("claims mismatch on full token: %v", clFull)
	}

	// SignClaims with empty Issuer/Audience uses ExpectedIssuer/ExpectedAudience
	tokAutoIssAud, err := v.SignClaims(nil, StandardClaims{
		Subject:   "auto-iss-aud",
		ExpiresAt: now + 3600,
	})
	if err != nil {
		t.Fatalf("SignClaims auto iss/aud failed: %v", err)
	}
	var clAuto Claims
	if err := v.Verify(tokAutoIssAud, now, &clAuto); err != nil {
		t.Fatalf("Verify auto iss/aud token failed: %v", err)
	}
	if string(clAuto.Issuer()) != "auth.zerojwt.io" || string(clAuto.Audience()) != "api.zerojwt.io" {
		t.Fatalf("expected auto populated issuer and audience: %s / %s", clAuto.Issuer(), clAuto.Audience())
	}

	// 4. VerifyAndIterate edge cases
	// Array payload in VerifyAndIterate
	tokArr, _ := v.Sign(nil, []byte(`["array","payload"]`))
	if err := v.VerifyAndIterate(tokArr, now, nil); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for array in VerifyAndIterate, got %v", err)
	}
	// Early break in VerifyAndIterate (fn returns false)
	iterBreakCount := 0
	err = v.VerifyAndIterate(tokClaimsFull, now, func(k, val []byte, isStr bool) bool {
		iterBreakCount++
		return false // break immediately
	})
	if err != nil || iterBreakCount != 1 {
		t.Fatalf("expected early break at 1 in VerifyAndIterate, got count=%d, err=%v", iterBreakCount, err)
	}

	// 5. validatePayloadClaims branches
	// Duplicate exp in payload
	tokDupExp, _ := v.Sign(nil, []byte(fmt.Sprintf(`{"exp":%d,"exp":%d}`, now+1000, now+2000)))
	if err := v.VerifyAndIterate(tokDupExp, now, nil); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for duplicate exp, got %v", err)
	}
	// Exp as string in payload
	tokExpStr, _ := v.Sign(nil, []byte(`{"exp":"invalid_str"}`))
	if err := v.VerifyAndIterate(tokExpStr, now, nil); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for exp as string, got %v", err)
	}
	// Exp invalid numeric (e.g. boolean)
	tokExpBadNum, _ := v.Sign(nil, []byte(`{"exp":true}`))
	if err := v.VerifyAndIterate(tokExpBadNum, now, nil); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for invalid exp number, got %v", err)
	}
	// Duplicate nbf
	tokDupNbf, _ := v.Sign(nil, []byte(fmt.Sprintf(`{"exp":%d,"nbf":%d,"nbf":%d}`, now+1000, now-10, now-5)))
	if err := v.VerifyAndIterate(tokDupNbf, now, nil); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for duplicate nbf, got %v", err)
	}
	// Nbf as string
	tokNbfStr, _ := v.Sign(nil, []byte(fmt.Sprintf(`{"exp":%d,"nbf":"invalid_str"}`, now+1000)))
	if err := v.VerifyAndIterate(tokNbfStr, now, nil); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for nbf as string, got %v", err)
	}
	// Nbf invalid numeric (e.g. boolean)
	tokNbfBadNum, _ := v.Sign(nil, []byte(fmt.Sprintf(`{"exp":%d,"nbf":true}`, now+1000)))
	if err := v.VerifyAndIterate(tokNbfBadNum, now, nil); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for invalid nbf number, got %v", err)
	}
	// Duplicate iss
	tokDupIss, _ := v.Sign(nil, []byte(fmt.Sprintf(`{"exp":%d,"iss":"auth.zerojwt.io","iss":"auth.zerojwt.io","aud":"api.zerojwt.io"}`, now+1000)))
	if err := v.VerifyAndIterate(tokDupIss, now, nil); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for duplicate iss in VerifyAndIterate, got %v", err)
	}
	// Duplicate aud
	tokDupAud, _ := v.Sign(nil, []byte(fmt.Sprintf(`{"exp":%d,"iss":"auth.zerojwt.io","aud":"api.zerojwt.io","aud":"api.zerojwt.io"}`, now+1000)))
	if err := v.VerifyAndIterate(tokDupAud, now, nil); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for duplicate aud in VerifyAndIterate, got %v", err)
	}
	// Iss as non-string
	tokIssNum, _ := v.Sign(nil, []byte(fmt.Sprintf(`{"exp":%d,"iss":12345}`, now+1000)))
	if err := v.VerifyAndIterate(tokIssNum, now, nil); !errors.Is(err, ErrInvalidIssuer) {
		t.Fatalf("expected ErrInvalidIssuer for numeric iss, got %v", err)
	}
	// Iss escaped (verify Pass 1 does not corrupt payload for Pass 2 callback)
	tokIssEsc, _ := v.Sign(nil, []byte(fmt.Sprintf(`{"exp":%d,"iss":"auth\u002ezerojwt\u002eio","aud":"api.zerojwt.io","role":"admin"}`, now+1000)))
	var seenIss, seenRole string
	if err := v.VerifyAndIterate(tokIssEsc, now, func(k, val []byte, isStr bool) bool {
		switch string(k) {
		case "iss":
			seenIss = string(val)
		case "role":
			seenRole = string(val)
		}
		return true
	}); err != nil {
		t.Fatalf("expected success for escaped iss, got %v", err)
	}
	if seenIss != `auth\u002ezerojwt\u002eio` || seenRole != "admin" {
		t.Fatalf("Pass 1 mutated payload buffer! seenIss=%q seenRole=%q", seenIss, seenRole)
	}
	// Aud mismatch
	tokAudBad, _ := v.Sign(nil, []byte(fmt.Sprintf(`{"exp":%d,"iss":"auth.zerojwt.io","aud":"wrong.aud"}`, now+1000)))
	if err := v.VerifyAndIterate(tokAudBad, now, nil); !errors.Is(err, ErrInvalidAudience) {
		t.Fatalf("expected ErrInvalidAudience for wrong aud, got %v", err)
	}
	// Missing required exp
	vReqExp, _ := New(secret)
	tokNoExp, _ := v.Sign(nil, []byte(`{"sub":"alice"}`))
	if err := vReqExp.VerifyAndIterate(tokNoExp, now, nil); !errors.Is(err, ErrMissingExp) {
		t.Fatalf("expected ErrMissingExp in VerifyAndIterate, got %v", err)
	}
	// Missing required iss
	tokNoIss, _ := v.Sign(nil, []byte(fmt.Sprintf(`{"exp":%d,"aud":"api.zerojwt.io"}`, now+1000)))
	if err := v.VerifyAndIterate(tokNoIss, now, nil); !errors.Is(err, ErrInvalidIssuer) {
		t.Fatalf("expected ErrInvalidIssuer when iss missing, got %v", err)
	}
	// Missing required aud
	tokNoAud, _ := v.Sign(nil, []byte(fmt.Sprintf(`{"exp":%d,"iss":"auth.zerojwt.io"}`, now+1000)))
	if err := v.VerifyAndIterate(tokNoAud, now, nil); !errors.Is(err, ErrInvalidAudience) {
		t.Fatalf("expected ErrInvalidAudience when aud missing, got %v", err)
	}
	// Escaped quotes inside iss and aud during VerifyAndIterate (regression test for in-place unescape corruption)
	vEscQuote, err := New(secret, Options{
		ExpectedIssuer:   `auth"quote`,
		ExpectedAudience: `api"quote`,
	})
	if err != nil {
		t.Fatal(err)
	}
	tokEscQuote, _ := vEscQuote.Sign(nil, []byte(fmt.Sprintf(`{"exp":%d,"iss":"auth\"quote","aud":["other","api\"quote"],"after":"ok"}`, now+1000)))
	var afterVal string
	if err := vEscQuote.VerifyAndIterate(tokEscQuote, now, func(k, val []byte, isStr bool) bool {
		if string(k) == "after" {
			afterVal = string(val)
		}
		return true
	}); err != nil || afterVal != "ok" {
		t.Fatalf("VerifyAndIterate with escaped quotes in iss/aud failed: err=%v after=%q", err, afterVal)
	}

	// 6. Iter iterator branches
	// Array payload in Iter
	for _, itErr := range v.Iter(tokArr, now) {
		if !errors.Is(itErr, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload in Iter for array payload, got %v", itErr)
		}
	}
	// Early break in Iter
	iterBreakCount = 0
	for prop, itErr := range v.Iter(tokClaimsFull, now) {
		if itErr != nil {
			t.Fatal(itErr)
		}
		if prop.Key != nil {
			iterBreakCount++
			break // test early return
		}
	}
	if iterBreakCount != 1 {
		t.Fatalf("expected early break at 1 in Iter, got %d", iterBreakCount)
	}

	// 7. iter.go helper branches (when errOut is omitted or nil)
	// ArrayElements without errOut
	for range ArrayElements([]byte("not_an_array")) {
	}
	for range ArrayElements([]byte(`["admin", `)) {
	}
	// ArrayElements with nil errOut
	for range ArrayElements([]byte("not_an_array"), nil) {
	}
	for range ArrayElements([]byte(`["admin", `), nil) {
	}

	// ObjectProps without errOut
	for range ObjectProps([]byte("not_an_object")) {
	}
	for range ObjectProps([]byte(`{"admin": `)) {
	}
	// ObjectProps with nil errOut
	for range ObjectProps([]byte("not_an_object"), nil) {
	}
	for range ObjectProps([]byte(`{"admin": `), nil) {
	}

	// ObjectProperties without errOut
	for range ObjectProperties([]byte("not_an_object")) {
	}
	for range ObjectProperties([]byte(`{"admin": `)) {
	}
	// ObjectProperties with nil errOut
	for range ObjectProperties([]byte("not_an_object"), nil) {
	}
	for range ObjectProperties([]byte(`{"admin": `), nil) {
	}

	// 8. Key rotation signature verification with EdDSA and ES256
	edPubK, edPrivK, _ := ed25519.GenerateKey(rand.Reader)
	vEdRot, _ := New(nil, Options{
		Algorithm:   AlgEdDSA,
		ActiveKeyID: "ed-k1",
		Keys: []Key{
			{ID: "ed-k1", Ed25519Public: edPubK},
		},
		Ed25519PrivateKey: edPrivK,
	})
	tokEdRot, err := vEdRot.SignClaims(nil, StandardClaims{Subject: "ed-rot", ExpiresAt: now + 3600})
	if err != nil {
		t.Fatalf("SignClaims EdDSA rotation failed: %v", err)
	}
	var clEd Claims
	if err := vEdRot.Verify(tokEdRot, now, &clEd); err != nil {
		t.Fatalf("Verify EdDSA rotation failed: %v", err)
	}

	ecPrivK, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	vEcRot, _ := New(nil, Options{
		Algorithm:   AlgES256,
		ActiveKeyID: "ec-k1",
		Keys: []Key{
			{ID: "ec-k1", ECDSAPublic: &ecPrivK.PublicKey},
		},
		ECDSAPrivateKey: ecPrivK,
	})
	tokEcRot, err := vEcRot.SignClaims(nil, StandardClaims{Subject: "ec-rot", ExpiresAt: now + 3600})
	if err != nil {
		t.Fatalf("SignClaims ES256 rotation failed: %v", err)
	}
	var clEc Claims
	if err := vEcRot.Verify(tokEcRot, now, &clEc); err != nil {
		t.Fatalf("Verify ES256 rotation failed: %v", err)
	}

	// 9. Numeric SubjectID in Claims
	tokNumSub, err := v.SignClaims(nil, StandardClaims{
		Subject:   "987654321",
		ExpiresAt: now + 3600,
	})
	if err != nil {
		t.Fatal(err)
	}
	var clNum Claims
	if err := v.Verify(tokNumSub, now, &clNum); err != nil {
		t.Fatal(err)
	}
	if clNum.SubjectID != 987654321 {
		t.Fatalf("expected SubjectID 987654321, got %d", clNum.SubjectID)
	}

	// 10. parseStandardClaims missing subject
	var clNoSub Claims
	if err := v.parseStandardClaims([]byte(fmt.Sprintf(`{"exp":%d,"iss":"auth.zerojwt.io","aud":"api.zerojwt.io"}`, now+1000)), now, &clNoSub); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for missing sub in parseStandardClaims, got %v", err)
	}

	// 11. Header validation afterComma empty
	hdrTrailingComma := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256",   }`))
	if _, err := v.validateHeader([]byte(hdrTrailingComma)); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for trailing comma in header, got %v", err)
	}

	// 12. verifySignatureAndDecodePayload empty payload
	b64Hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	b64EmptyPl := base64.RawURLEncoding.EncodeToString([]byte(``))
	tokEmptyPl := []byte(b64Hdr + "." + b64EmptyPl + ".c2ln")
	if _, err := v.verifySignatureAndDecodePayload(tokEmptyPl, st); err == nil {
		t.Fatal("expected error for empty payload base64")
	}

	// 13. Iter error on verifySignatureAndDecodePayload
	iterCalls := 0
	for _, itErr := range v.Iter([]byte("bad.token.sig"), now) {
		iterCalls++
		if itErr == nil {
			t.Fatal("expected error from Iter on invalid token")
		}
	}
	if iterCalls != 1 {
		t.Fatalf("expected 1 error yield in Iter, got %d", iterCalls)
	}

	// 14. newVerifier with empty Algorithm uses default HS256
	vDefaultAlg, err := newVerifier(secret, Options{})
	if err != nil || vDefaultAlg.alg != AlgHS256 {
		t.Fatalf("expected default AlgHS256, got %v", vDefaultAlg.alg)
	}

	// 15. SignClaims on verify-only node returns ErrNoSigningKey
	vVerifyOnly, _ := NewEd25519Verifier(edPubK, nil)
	if _, err := vVerifyOnly.SignClaims(nil, StandardClaims{Subject: "alice", ExpiresAt: 100}); !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("expected ErrNoSigningKey, got %v", err)
	}

	// 16. parseStandardClaims with zeroMemory == true
	vZMem, _ := New(secret, Options{ZeroMemory: true})
	var clZMem Claims
	if err := vZMem.parseStandardClaims([]byte(fmt.Sprintf(`{"sub":"zmem","exp":%d}`, now+1000)), now, &clZMem); err != nil {
		t.Fatalf("expected parseStandardClaims to succeed with ZeroMemory, got %v", err)
	}

	// 17. parseStandardClaims non-object payload & syntax error
	if err := v.parseStandardClaims([]byte(`["array"]`), now, &clNoSub); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for array in parseStandardClaims, got %v", err)
	}
	if err := v.parseStandardClaims([]byte(`{"sub":"u", bad}`), now, &clNoSub); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for syntax error in parseStandardClaims, got %v", err)
	}

	// 18. parseStandardClaims invalid numeric for exp, nbf, iat
	if err := v.parseStandardClaims([]byte(`{"sub":"u","exp":123bad}`), now, &clNoSub); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for bad exp numeric, got %v", err)
	}
	if err := v.parseStandardClaims([]byte(`{"sub":"u","nbf":123bad}`), now, &clNoSub); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for bad nbf numeric, got %v", err)
	}
	if err := v.parseStandardClaims([]byte(`{"sub":"u","iat":123bad}`), now, &clNoSub); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for bad iat numeric, got %v", err)
	}

	// 19. parseStandardClaims aud branches
	if err := v.parseStandardClaims([]byte(fmt.Sprintf(`{"sub":"u","exp":%d,"aud":"other.aud"}`, now+1000)), now, &clNoSub); !errors.Is(err, ErrInvalidAudience) {
		t.Fatalf("expected ErrInvalidAudience for aud mismatch, got %v", err)
	}
	if err := v.parseStandardClaims([]byte(fmt.Sprintf(`{"sub":"u","exp":%d,"aud":["other1","other2"]}`, now+1000)), now, &clNoSub); !errors.Is(err, ErrInvalidAudience) {
		t.Fatalf("expected ErrInvalidAudience for aud array mismatch, got %v", err)
	}
	if err := v.parseStandardClaims([]byte(fmt.Sprintf(`{"sub":"u","exp":%d,"aud":12345}`, now+1000)), now, &clNoSub); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for numeric aud, got %v", err)
	}

	// 20. Scanner branches
	if _, _, _, _, ok := NextJSONProp([]byte("  , , ")); ok {
		t.Fatal("expected false for whitespace and commas in NextJSONProp")
	}
	if _, _, _, _, ok := NextJSONProp([]byte("key: 123")); ok {
		t.Fatal("expected false for unquoted key")
	}
	if k, _, _, _, ok := NextJSONProp([]byte(`"my\\key\n": 123`)); !ok || !bytes.Contains(k, []byte(`my\\key\n`)) {
		t.Fatalf("expected key with escape sequence, got %s", k)
	}
	if _, _, _, _, ok := NextJSONProp([]byte(`"key"   : 123`)); !ok {
		t.Fatal("expected ok with whitespace before colon")
	}
	if _, _, _, _, ok := NextJSONProp([]byte(`"nested": {"a": {"b": 1}}`)); !ok {
		t.Fatal("expected ok for nested object inside object")
	}
	if _, _, _, _, ok := NextJSONProp([]byte(`"nested": [[[1]]]`)); !ok {
		t.Fatal("expected ok for nested array inside array")
	}
	if _, _, _, _, ok := NextJSONProp([]byte(`"nested": ["str\\\"ing"]`)); !ok {
		t.Fatal("expected ok for escaped string in nested array")
	}

	// 21. iter.go error when second element has syntax error
	var errEl error
	for range ArrayElements([]byte(`["admin", unclosed]`), &errEl) {
	}
	if !errors.Is(errEl, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload on array element 2, got %v", errEl)
	}
	for range ObjectProps([]byte(`{"k1": "v1", "k2": unclosed}`), &errEl) {
	}
	if !errors.Is(errEl, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload on object prop 2, got %v", errEl)
	}
	for range ObjectProperties([]byte(`{"k1": "v1", "k2": unclosed}`), &errEl) {
	}
	if !errors.Is(errEl, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload on object properties 2, got %v", errEl)
	}

	// 22. validatePayloadClaims syntax error
	if err := v.validatePayloadClaims([]byte(`{"sub":"u", bad}`), now); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for syntax error in validatePayloadClaims, got %v", err)
	}

	// 23. verifySignatureAndDecodePayload dot permutations
	if _, err := v.verifySignatureAndDecodePayload([]byte(".b.c"), st); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for leading dot, got %v", err)
	}
	if _, err := v.verifySignatureAndDecodePayload([]byte("a..c"), st); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for empty payload segment, got %v", err)
	}
	if _, err := v.verifySignatureAndDecodePayload([]byte("a.b."), st); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for empty sig segment, got %v", err)
	}
	if _, err := v.verifySignatureAndDecodePayload([]byte("a.b.c.d"), st); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for extra dot, got %v", err)
	}
	if _, err := v.verifySignatureAndDecodePayload([]byte("a\rb.c.d"), st); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken for CR, got %v", err)
	}

	// 24. decodeDERToP1363 with s > 32 bytes
	longSBytes := append([]byte{0x30, 0x26, 0x02, 0x01, 0x01, 0x02, 0x21}, bytes.Repeat([]byte{0x01}, 33)...)
	var rawSigOut [64]byte
	if decodeDERToP1363(longSBytes, rawSigOut[:]) {
		t.Fatal("expected false for s > 32 bytes")
	}

	// 25. ErrSigningFailed with failing randReader
	vEcErr, _ := NewES256Verifier(&ecPriv.PublicKey, ecPriv)
	vEcErr.randReader = errReader{}
	if _, err := vEcErr.Sign(nil, []byte(`{"sub":"alice"}`)); !errors.Is(err, ErrSigningFailed) {
		t.Fatalf("expected ErrSigningFailed, got %v", err)
	}

	// 26. parseStandardClaims branches in Verify
	tokExpVerify, _ := v.Sign(nil, []byte(fmt.Sprintf(`{"sub":"alice","exp":%d}`, now-100)))
	var clVerify Claims
	if err := v.Verify(tokExpVerify, now, &clVerify); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired in Verify, got %v", err)
	}

	tokNbfVerify, _ := v.Sign(nil, []byte(fmt.Sprintf(`{"sub":"alice","nbf":%d,"exp":%d}`, now+1000, now+2000)))
	if err := v.Verify(tokNbfVerify, now, &clVerify); !errors.Is(err, ErrTokenNotValidYet) {
		t.Fatalf("expected ErrTokenNotValidYet in Verify, got %v", err)
	}

	tokIssVerify, _ := v.Sign(nil, []byte(fmt.Sprintf(`{"sub":"alice","iss":"wrong.iss","exp":%d}`, now+1000)))
	if err := v.Verify(tokIssVerify, now, &clVerify); !errors.Is(err, ErrInvalidIssuer) {
		t.Fatalf("expected ErrInvalidIssuer in Verify, got %v", err)
	}

	// 27. Signature length bounds in verifySignatureAndDecodePayload
	bigSig := base64.RawURLEncoding.EncodeToString(make([]byte, 600))
	tokBigSig := []byte("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0." + bigSig)
	if _, err := v.verifySignatureAndDecodePayload(tokBigSig, st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for sig > 512 bytes, got %v", err)
	}

	shortSig := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	tokShortSig := []byte("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0." + shortSig)
	if _, err := v.verifySignatureAndDecodePayload(tokShortSig, st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for sig != sigDecodedLen, got %v", err)
	}

	// 28. Rotated keys verification failures
	dummySig64 := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 64))
	dummySig32 := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))

	// EdDSA invalid signature (hits ed25519.Verify == false -> line 998)
	hdrEdRot := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"ed-k1"}`))
	tokEdBadSig := []byte(hdrEdRot + ".eyJzdWIiOiIxIn0." + dummySig64)
	if _, err := vEdRot.verifySignatureAndDecodePayload(tokEdBadSig, st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for EdDSA invalid signature, got %v", err)
	}

	// Rotated key with bad Ed25519 pub size (hits len(pub) != ed25519.PublicKeySize -> line 998)
	vEdBadPub := &Verifier{
		alg:           AlgEdDSA,
		algBytes:      []byte(AlgEdDSA),
		sigDecodedLen: 64,
		keys: []compiledKey{
			{idBytes: []byte("ed-bad"), ed25519Public: make([]byte, 16)},
		},
	}
	hdrEdBad := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"ed-bad"}`))
	tokEdBadPub := []byte(hdrEdBad + ".eyJzdWIiOiIxIn0." + dummySig64)
	if _, err := vEdBadPub.verifySignatureAndDecodePayload(tokEdBadPub, st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for bad Ed25519 pub length, got %v", err)
	}

	// Rotated key with nil ECDSA pub (hits pub == nil -> line 1006)
	vEcNilPub := &Verifier{
		alg:           AlgES256,
		algBytes:      []byte(AlgES256),
		sigDecodedLen: 64,
		keys: []compiledKey{
			{idBytes: []byte("ec-nil"), ecdsaPublic: nil},
		},
	}
	hdrEcNil := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"ec-nil"}`))
	tokEcNilPub := []byte(hdrEcNil + ".eyJzdWIiOiIxIn0." + dummySig64)
	if _, err := vEcNilPub.verifySignatureAndDecodePayload(tokEcNilPub, st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for nil ECDSA pub, got %v", err)
	}

	// ES256 invalid signature (hits ecdsa.VerifyASN1 == false -> line 1014)
	hdrEcRot := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"ec-k1"}`))
	tokEcBadSig := []byte(hdrEcRot + ".eyJzdWIiOiIxIn0." + dummySig64)
	if _, err := vEcRot.verifySignatureAndDecodePayload(tokEcBadSig, st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for ES256 invalid signature, got %v", err)
	}

	// Rotated key with empty secret (hits len(v.keys[keyIdx].secret) == 0 -> line 1020)
	vHSEmptySec := &Verifier{
		alg:           AlgHS256,
		algBytes:      []byte(AlgHS256),
		sigDecodedLen: 32,
		keys: []compiledKey{
			{idBytes: []byte("hs-empty"), secret: nil},
		},
	}
	hdrHSEmpty := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":"hs-empty"}`))
	tokHSEmpty := []byte(hdrHSEmpty + ".eyJzdWIiOiIxIn0." + dummySig32)
	if _, err := vHSEmptySec.verifySignatureAndDecodePayload(tokHSEmpty, st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature for empty key secret, got %v", err)
	}

	// Verifier with empty secret in verifySignatureAndDecodePayload (hits len(v.secret) == 0 -> line 1024)
	vEmptySec := &Verifier{alg: AlgHS256, algBytes: []byte("HS256"), sigDecodedLen: 32}
	tokEmptySec := []byte("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0." + dummySig32)
	if _, err := vEmptySec.verifySignatureAndDecodePayload(tokEmptySec, st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature when verifier secret is empty, got %v", err)
	}

	// Rotated key HMAC mismatch (hits !hmac.Equal -> line 1030)
	vHSRot, _ := New(secret, Options{
		Keys: []Key{
			{ID: "hs-k1", Secret: bytes.Repeat([]byte("1"), 32)},
		},
	})
	stHSRot := vHSRot.NewScratch()
	hdrHSRot := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":"hs-k1"}`))
	tokHSRotBad := []byte(hdrHSRot + ".eyJzdWIiOiIxIn0." + dummySig32)
	if _, err := vHSRot.verifySignatureAndDecodePayload(tokHSRotBad, stHSRot); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature on rotated key HMAC mismatch, got %v", err)
	}

	// Default key HMAC mismatch (hits !hmac.Equal -> line 1030)
	tokHSBadSig := []byte("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0." + dummySig32)
	if _, err := v.verifySignatureAndDecodePayload(tokHSBadSig, st); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature on default key HMAC mismatch, got %v", err)
	}

	// 29. Header parsing edge cases
	// Missing "alg"
	hdrNoAlg := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT"}`))
	tokNoAlg := []byte(hdrNoAlg + ".eyJzdWIiOiIxIn0." + dummySig32)
	if _, err := v.verifySignatureAndDecodePayload(tokNoAlg, st); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for missing alg header, got %v", err)
	}

	// Missing comma between header properties (hits line 1064)
	hdrNoComma := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256" "typ":"JWT"}`))
	tokNoComma := []byte(hdrNoComma + ".eyJzdWIiOiIxIn0." + dummySig32)
	if _, err := v.verifySignatureAndDecodePayload(tokNoComma, st); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for missing comma in header, got %v", err)
	}

	// Malformed property after comma in header (hits line 1074)
	hdrBadProp := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256", "bad": }`))
	tokBadProp := []byte(hdrBadProp + ".eyJzdWIiOiIxIn0." + dummySig32)
	if _, err := v.verifySignatureAndDecodePayload(tokBadProp, st); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for malformed property after comma, got %v", err)
	}

	// 30. Invalid base64 in payload with valid signature
	badB64Input := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.!!!not-base64!!!"
	macBadB64 := hmac.New(sha256.New, secret)
	macBadB64.Write([]byte(badB64Input))
	sigBadB64 := base64.RawURLEncoding.EncodeToString(macBadB64.Sum(nil))
	tokBadB64 := []byte(badB64Input + "." + sigBadB64)
	if _, err := v.verifySignatureAndDecodePayload(tokBadB64, st); !errors.Is(err, ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload for invalid base64 in payload, got %v", err)
	}

	// 31. matchAudienceClaim with escaped array element
	var capAud []byte
	if !matchAudienceClaim([]byte(`["api\u002ezerojwt\u002eio"]`), false, []byte("api.zerojwt.io"), &capAud) {
		t.Fatal("expected match for escaped array element in matchAudienceClaim")
	}

	// 32. decodeDERToP1363 with leading zeros in rBytes and sBytes
	var dstDER [64]byte
	derWithZeros := []byte{0x30, 0x08, 0x02, 0x02, 0x00, 0x01, 0x02, 0x02, 0x00, 0x02}
	if !decodeDERToP1363(derWithZeros, dstDER[:]) {
		t.Fatal("expected decodeDERToP1363 to succeed with leading zeros")
	}
}

type errReader struct{}

func (errReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("entropy source failed")
}
