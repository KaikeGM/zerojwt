package zerojwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	secA = "secret-A-secret-A-secret-A-32bytes" // 33 bytes
	secB = "secret-B-secret-B-secret-B-32bytes"
	tnow = int64(1700000000)
)

var b64 = base64.RawURLEncoding

// signRaw builds an HS256 token with an arbitrary header/payload and an arbitrary HMAC key
// (including an empty one), the way an attacker who knows no secret would.
func signRaw(key []byte, header, payload string) []byte {
	h := b64.EncodeToString([]byte(header))
	p := b64.EncodeToString([]byte(payload))
	m := hmac.New(sha256.New, key)
	m.Write([]byte(h + "." + p))
	return []byte(h + "." + p + "." + b64.EncodeToString(m.Sum(nil)))
}

func mustPanicWith(t *testing.T, target error, f func()) {
	t.Helper()
	defer func() {
		r := recover()
		err, ok := r.(error)
		if !ok || !errors.Is(err, target) {
			t.Fatalf("expected panic wrapping %v, got %v", target, r)
		}
	}()
	f()
}

// Regression: a Key without material for the selected algorithm used to be selectable by "kid"
// and verified with an EMPTY HMAC key (auth bypass in the README's rotation example).
func TestRegression_KeyWithoutSecretIsRejected(t *testing.T) {
	edPub, _, _ := ed25519.GenerateKey(nil)
	opts := Options{
		Algorithm:   AlgHS256,
		ActiveKeyID: "key-2026-v2",
		Keys: []Key{
			{ID: "key-2025-v1", Secret: []byte(secA)},
			{ID: "key-2026-v2", Secret: []byte(secB)},
			{ID: "key-ed-v1", Ed25519Public: edPub}, // no Secret
		},
	}
	if _, err := TryNewVerifier([]byte(secB), opts); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig, got %v", err)
	}
	mustPanicWith(t, ErrInvalidConfig, func() { NewVerifierWithOptions([]byte(secB), opts) })
}

// Defense in depth: even on a valid configuration, tokens signed with an empty key never verify,
// with or without "kid", including when only Keys (no primary secret) are configured.
func TestRegression_EmptyKeyForgeryRejected(t *testing.T) {
	v := NewVerifierWithOptions(nil, Options{
		Keys: []Key{{ID: "k1", Secret: []byte(secA)}},
	})
	payload := `{"sub":"admin","exp":4102444800}`
	for name, hdr := range map[string]string{
		"with kid":    `{"alg":"HS256","typ":"JWT","kid":"k1"}`,
		"without kid": `{"alg":"HS256","typ":"JWT"}`,
	} {
		var c Claims
		if err := v.Verify(signRaw(nil, hdr, payload), tnow, &c); !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("%s: forged empty-key token must fail with ErrInvalidSignature, got %v", name, err)
		}
	}
	// The legitimate token for the same verifier still works.
	var c Claims
	good := signRaw([]byte(secA), `{"alg":"HS256","typ":"JWT","kid":"k1"}`, payload)
	if err := v.Verify(good, tnow, &c); err != nil || string(c.Subject()) != "admin" {
		t.Fatalf("legit token rejected: %v", err)
	}
}

func TestRegression_EmptySecretIsConfigError(t *testing.T) {
	for name, secret := range map[string][]byte{"nil": nil, "empty": {}} {
		if _, err := TryNewVerifier(secret, Options{}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s secret: expected ErrInvalidConfig, got %v", name, err)
		}
	}
	mustPanicWith(t, ErrInvalidConfig, func() { NewVerifier(nil) })
}

func TestConfigValidationMatrix(t *testing.T) {
	edPub, edPriv, _ := ed25519.GenerateKey(nil)
	ec256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ec384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	bad := map[string]struct {
		secret []byte
		opts   Options
	}{
		"unknown algorithm":    {[]byte(secA), Options{Algorithm: "RS256"}},
		"typo algorithm":       {[]byte(secA), Options{Algorithm: "hs256"}},
		"key with empty ID":    {[]byte(secA), Options{Keys: []Key{{Secret: []byte(secA)}}}},
		"duplicate key IDs":    {[]byte(secA), Options{Keys: []Key{{ID: "a", Secret: []byte(secA)}, {ID: "a", Secret: []byte(secB)}}}},
		"HS key empty secret":  {[]byte(secA), Options{Keys: []Key{{ID: "a"}}}},
		"EdDSA no key at all":  {nil, Options{Algorithm: AlgEdDSA}},
		"EdDSA short pub":      {nil, Options{Algorithm: AlgEdDSA, Ed25519PublicKey: edPub[:16]}},
		"EdDSA short priv":     {nil, Options{Algorithm: AlgEdDSA, Ed25519PublicKey: edPub, Ed25519PrivateKey: edPriv[:32]}},
		"EdDSA key wrong type": {nil, Options{Algorithm: AlgEdDSA, Keys: []Key{{ID: "a", Secret: []byte(secA)}}}},
		"ES256 no key at all":  {nil, Options{Algorithm: AlgES256}},
		"ES256 P-384 pub":      {nil, Options{Algorithm: AlgES256, ECDSAPublicKey: &ec384.PublicKey}},
		"ES256 P-384 priv":     {nil, Options{Algorithm: AlgES256, ECDSAPrivateKey: ec384}},
		"ES256 P-384 key":      {nil, Options{Algorithm: AlgES256, Keys: []Key{{ID: "a", ECDSAPublic: &ec384.PublicKey}}}},
		"ES256 key nil":        {nil, Options{Algorithm: AlgES256, Keys: []Key{{ID: "a"}}}},
		"strict HS256 short":   {[]byte(strings.Repeat("x", 31)), Options{StrictSecretLength: true}},
		"strict HS384 short":   {[]byte(strings.Repeat("x", 47)), Options{Algorithm: AlgHS384, StrictSecretLength: true}},
		"strict HS512 short":   {[]byte(strings.Repeat("x", 63)), Options{Algorithm: AlgHS512, StrictSecretLength: true}},
		"strict key too short": {[]byte(secA), Options{StrictSecretLength: true, Keys: []Key{{ID: "a", Secret: []byte("short")}}}},
		"sub-second leeway":    {[]byte(secA), Options{Leeway: 500 * time.Millisecond}},
	}
	for name, c := range bad {
		if _, err := TryNewVerifier(c.secret, c.opts); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: expected ErrInvalidConfig, got %v", name, err)
		}
	}

	good := map[string]struct {
		secret []byte
		opts   Options
	}{
		"short secret by default (compat)": {[]byte("twelve-dollar-challenge"), Options{}},
		"strict HS256 32 bytes":            {[]byte(strings.Repeat("x", 32)), Options{StrictSecretLength: true}},
		"strict HS512 64 bytes":            {[]byte(strings.Repeat("x", 64)), Options{Algorithm: AlgHS512, StrictSecretLength: true}},
		"HS keys only":                     {nil, Options{Keys: []Key{{ID: "a", Secret: []byte(secA)}}}},
		"EdDSA pub only":                   {nil, Options{Algorithm: AlgEdDSA, Ed25519PublicKey: edPub}},
		"EdDSA priv only":                  {nil, Options{Algorithm: AlgEdDSA, Ed25519PrivateKey: edPriv}},
		"ES256 pub only":                   {nil, Options{Algorithm: AlgES256, ECDSAPublicKey: &ec256.PublicKey}},
		"ES256 priv only":                  {nil, Options{Algorithm: AlgES256, ECDSAPrivateKey: ec256}},
	}
	for name, c := range good {
		if _, err := TryNewVerifier(c.secret, c.opts); err != nil {
			t.Errorf("%s: unexpected error %v", name, err)
		}
	}
}

func TestRegression_SignRefusesWithoutKey(t *testing.T) {
	edPub, _, _ := ed25519.GenerateKey(nil)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	verifyOnly := map[string]*Verifier{
		"EdDSA": NewEd25519Verifier(edPub, nil, Options{}),
		"ES256": NewES256Verifier(&ec.PublicKey, nil, Options{}),
		"HS256 keys only": NewVerifierWithOptions(nil, Options{
			Keys: []Key{{ID: "a", Secret: []byte(secA)}},
		}),
	}
	for name, v := range verifyOnly {
		if v.CanSign() {
			t.Errorf("%s: CanSign must be false", name)
		}
		if tok := v.Sign(nil, []byte(`{"sub":"1"}`)); tok != nil {
			t.Errorf("%s: Sign must return nil, got %q", name, tok)
		}
		if tok := v.SignClaims(nil, []byte("1"), nil, tnow, tnow+60); tok != nil {
			t.Errorf("%s: SignClaims must return nil, got %q", name, tok)
		}
		b := v.NewSigner(nil)
		if tok, err := b.SetSubject([]byte("1")).Sign(); tok != nil || !errors.Is(err, ErrNoSigningKey) {
			t.Errorf("%s: SignBuilder.Sign want (nil, ErrNoSigningKey), got (%q, %v)", name, tok, err)
		}
	}
	if !NewVerifier([]byte(secA)).CanSign() {
		t.Fatal("HS256 verifier with a secret must be able to sign")
	}
}

func TestPrivateKeyOnlySignerVerifiesOwnTokens(t *testing.T) {
	_, edPriv, _ := ed25519.GenerateKey(nil)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, v := range map[string]*Verifier{
		"EdDSA": NewEd25519Verifier(nil, edPriv, Options{}),
		"ES256": NewES256Verifier(nil, ec, Options{}),
	} {
		tok := v.SignClaims(nil, []byte("42"), []byte("u"), tnow, tnow+60)
		var c Claims
		if err := v.Verify(tok, tnow, &c); err != nil || c.SubjectID != 42 {
			t.Errorf("%s: round trip failed: %v", name, err)
		}
	}
}

func TestRequireExp(t *testing.T) {
	loose := NewVerifier([]byte(secA))
	strict := NewVerifierWithOptions([]byte(secA), Options{RequireExp: true})

	noExp := loose.SignClaims(nil, []byte("u"), nil, tnow, 0)
	if noExp == nil {
		t.Fatal("default verifier must keep signing exp-less tokens (backward compatible)")
	}
	var c Claims
	if err := loose.Verify(noExp, tnow+10_000_000, &c); err != nil {
		t.Fatalf("default verifier must keep accepting exp-less tokens: %v", err)
	}

	if err := strict.Verify(noExp, tnow, &c); !errors.Is(err, ErrMissingExp) {
		t.Errorf("Verify: want ErrMissingExp, got %v", err)
	}
	var cl ClaimsLarge
	if err := strict.VerifyLarge(noExp, tnow, &cl); !errors.Is(err, ErrMissingExp) {
		t.Errorf("VerifyLarge: want ErrMissingExp, got %v", err)
	}
	if err := strict.VerifyCustom(noExp, tnow, nil); !errors.Is(err, ErrMissingExp) {
		t.Errorf("VerifyCustom: want ErrMissingExp, got %v", err)
	}

	if tok := strict.SignClaims(nil, []byte("u"), nil, tnow, 0); tok != nil {
		t.Error("RequireExp verifier must refuse SignClaims with exp <= 0")
	}
	b := strict.NewSigner(nil)
	if tok, err := b.SetSubject([]byte("u")).Sign(); tok != nil || !errors.Is(err, ErrMissingExp) {
		t.Errorf("SignBuilder without exp: want (nil, ErrMissingExp), got (%q, %v)", tok, err)
	}

	ok := strict.SignClaims(nil, []byte("u"), nil, tnow, tnow+60)
	if err := strict.Verify(ok, tnow, &c); err != nil {
		t.Errorf("token with exp rejected: %v", err)
	}
	if err := strict.VerifyCustom(ok, tnow, nil); err != nil {
		t.Errorf("VerifyCustom with exp rejected: %v", err)
	}
	b2 := strict.NewSigner(nil)
	tok, err := b2.SetSubject([]byte("u")).SetExpiresAt(tnow + 60).Sign()
	if err != nil || strict.Verify(tok, tnow, &c) != nil {
		t.Errorf("builder with exp failed: %v", err)
	}
}

// Regression: trailing CR/LF and non-canonical Base64URL padding bits used to be accepted,
// giving every token many distinct valid string forms (breaks token-string revocation/caching).
func TestRegression_TokenHasSingleAcceptedForm(t *testing.T) {
	edPub, edPriv, _ := ed25519.GenerateKey(nil)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	vs := map[string]*Verifier{
		"HS256": NewVerifier([]byte(secA)),
		"HS384": NewVerifierWithOptions([]byte(secA), Options{Algorithm: AlgHS384}),
		"HS512": NewVerifierWithOptions([]byte(secA), Options{Algorithm: AlgHS512}),
		"EdDSA": NewEd25519Verifier(edPub, edPriv, Options{}),
		"ES256": NewES256Verifier(&ec.PublicKey, ec, Options{}),
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for name, v := range vs {
		tok := append([]byte(nil), v.SignClaims(nil, []byte("u1"), []byte("a"), tnow, tnow+3600)...)
		var c Claims
		if err := v.Verify(tok, tnow, &c); err != nil {
			t.Fatalf("%s: valid token rejected: %v", name, err)
		}
		for _, suffix := range []string{"\n", "\r", "\r\n"} {
			if err := v.Verify(append(append([]byte(nil), tok...), suffix...), tnow, &c); err == nil {
				t.Errorf("%s: token + %q accepted", name, suffix)
			}
		}
		// Insert a newline in the middle of the signature segment.
		mid := append([]byte(nil), tok...)
		i := len(mid) - 10
		mid = append(mid[:i], append([]byte{'\n'}, mid[i:]...)...)
		if err := v.Verify(mid, tnow, &c); err == nil {
			t.Errorf("%s: token with embedded newline accepted", name)
		}
		// Every other final character must be rejected (different bits, or non-canonical padding bits).
		last := tok[len(tok)-1]
		for i := 0; i < len(alphabet); i++ {
			if alphabet[i] == last {
				continue
			}
			alt := append([]byte(nil), tok...)
			alt[len(alt)-1] = alphabet[i]
			if err := v.Verify(alt, tnow, &c); err == nil {
				t.Errorf("%s: variant with last char %q accepted", name, alphabet[i])
			}
		}
	}
}

func TestRegression_CritHeaderRejected(t *testing.T) {
	v := NewVerifier([]byte(secA))
	var c Claims
	tok := signRaw([]byte(secA), `{"alg":"HS256","typ":"JWT","crit":["exp"]}`, `{"sub":"u","exp":4102444800}`)
	if err := v.Verify(tok, tnow, &c); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("token with crit header must be rejected with ErrInvalidHeader, got %v", err)
	}
	plain := signRaw([]byte(secA), `{"alg":"HS256","typ":"JWT"}`, `{"sub":"u","exp":4102444800}`)
	if err := v.Verify(plain, tnow, &c); err != nil {
		t.Fatalf("control token rejected: %v", err)
	}
}

func TestDestroyFailsClosed(t *testing.T) {
	v := NewVerifier([]byte(secA))
	tok := append([]byte(nil), v.SignClaims(nil, []byte("u"), nil, tnow, tnow+60)...)
	var c Claims
	if err := v.Verify(tok, tnow, &c); err != nil {
		t.Fatal(err)
	}
	v.Destroy()
	if err := v.Verify(tok, tnow, &c); !errors.Is(err, ErrVerifierDestroyed) {
		t.Errorf("Verify after Destroy: want ErrVerifierDestroyed, got %v", err)
	}
	if err := v.VerifyCustom(tok, tnow, nil); !errors.Is(err, ErrVerifierDestroyed) {
		t.Errorf("VerifyCustom after Destroy: want ErrVerifierDestroyed, got %v", err)
	}
	if v.CanSign() || v.Sign(nil, []byte(`{"sub":"u"}`)) != nil {
		t.Error("Sign after Destroy must refuse")
	}
}

// The hardening must not cost allocations on the hot path (Strict() would, if built per call).
func TestHardeningKeepsZeroAllocs(t *testing.T) {
	if raceDetectorEnabled {
		t.Skip("allocation counts are not meaningful under the race detector")
	}
	edPub, edPriv, _ := ed25519.GenerateKey(nil)
	for name, v := range map[string]*Verifier{
		"HS256": NewVerifier([]byte(secA)),
		"EdDSA": NewEd25519Verifier(edPub, edPriv, Options{RequireExp: true}),
	} {
		var buf [512]byte
		tok := append([]byte(nil), v.SignClaims(buf[:0], []byte("u1"), []byte("a"), tnow, tnow+3600)...)
		var c Claims
		if n := testing.AllocsPerRun(100, func() { _ = v.Verify(tok, tnow, &c) }); n != 0 {
			t.Errorf("%s Verify allocs/op = %v, want 0", name, n)
		}
		if n := testing.AllocsPerRun(100, func() { _ = v.SignClaims(buf[:0], []byte("u1"), []byte("a"), tnow, tnow+3600) }); n != 0 {
			t.Errorf("%s SignClaims allocs/op = %v, want 0", name, n)
		}
	}
}

// Key rotation as documented (after the README fix) still works end to end.
func TestKeyRotationStillWorks(t *testing.T) {
	opts := Options{
		ActiveKeyID: "key-2026-v2",
		Keys: []Key{
			{ID: "key-2025-v1", Secret: []byte(secA)},
			{ID: "key-2026-v2", Secret: []byte(secB)},
		},
	}
	v := NewVerifierWithOptions([]byte(secB), opts)
	var c Claims
	if err := v.Verify(v.SignClaims(nil, []byte("7"), nil, tnow, tnow+60), tnow, &c); err != nil || c.SubjectID != 7 {
		t.Fatalf("active key round trip failed: %v", err)
	}
	old := signRaw([]byte(secA), `{"alg":"HS256","typ":"JWT","kid":"key-2025-v1"}`, `{"sub":"9","exp":4102444800}`)
	if err := v.Verify(old, tnow, &c); err != nil || c.SubjectID != 9 {
		t.Fatalf("token signed with the previous key rejected: %v", err)
	}
	unknown := signRaw([]byte(secA), `{"alg":"HS256","typ":"JWT","kid":"nope"}`, `{"sub":"9","exp":4102444800}`)
	if err := v.Verify(unknown, tnow, &c); !errors.Is(err, ErrUnknownKeyID) {
		t.Fatalf("unknown kid: want ErrUnknownKeyID, got %v", err)
	}
}

func TestSecurityHardeningFullCoverage(t *testing.T) {
	// 1. ES256 signing failure in SignHS256WithScratch
	validKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	badESPriv := &ecdsa.PrivateKey{PublicKey: validKey.PublicKey, D: validKey.Params().N}
	vBadES := &Verifier{alg: AlgES256, ecPriv: badESPriv, sigEncodedLen: 86, maxPayloadSize: 4096}
	vBadES.pool.New = func() any { return vBadES.NewScratch() }
	if tok := vBadES.SignHS256WithScratch(nil, []byte(`{"sub":"1"}`), vBadES.NewScratch()); tok != nil {
		t.Fatalf("expected nil on invalid ECDSA private key signing, got %v", tok)
	}

	// 2. ES256 verification when verifier has Keys but no primary key and token has no kid (pub == nil)
	ec256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	vKeysOnly := NewVerifierWithOptions(nil, Options{
		Algorithm: AlgES256,
		Keys:      []Key{{ID: "k1", ECDSAPublic: &ec256.PublicKey}},
	})
	dummySig := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	tokNoKid := []byte("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0." + dummySig)
	var c Claims
	if err := vKeysOnly.Verify(tokNoKid, tnow, &c); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature when pub == nil in ES256, got %v", err)
	}

	// 3. Verifier with cleared key secret on verification path
	vKeyEmpty := NewVerifierWithOptions([]byte(secA), Options{
		Keys: []Key{{ID: "k1", Secret: []byte(secA)}},
	})
	vKeyEmpty.keys[0].secret = nil
	tokWithKid := signRaw(nil, `{"alg":"HS256","typ":"JWT","kid":"k1"}`, `{"sub":"1"}`)
	if err := vKeyEmpty.Verify(tokWithKid, tnow, &c); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature when keys[i].secret is empty, got %v", err)
	}

	// 4. validateHeader when decoded header is not a JSON object
	vHS := NewVerifier([]byte(secA))
	nonObjHdr := base64.RawURLEncoding.EncodeToString([]byte(`"not-an-object"`))
	tokNonObj := []byte(nonObjHdr + ".eyJzdWIiOiIxMjMifQ.c2ln")
	if err := vHS.Verify(tokNonObj, tnow, &c); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader for non-object JSON header, got %v", err)
	}
}
