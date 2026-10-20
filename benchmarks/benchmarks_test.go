package benchmarks

import (
	"testing"
	"time"

	"github.com/KaikeGM/zerojwt"
	golangjwt "github.com/golang-jwt/jwt/v5"
	katarasjwt "github.com/kataras/jwt"
	"github.com/lestrrat-go/jwx/v2/jwa"
	jwxjwt "github.com/lestrrat-go/jwx/v2/jwt"
)

var benchmarkSecret = []byte("twelve-dollar-challenge-benchmark-secret-32b")

type standardClaims struct {
	User string `json:"user"`
	golangjwt.RegisteredClaims
}

type katarasClaims struct {
	Sub  string `json:"sub"`
	User string `json:"user"`
	Iat  int64  `json:"iat"`
	Exp  int64  `json:"exp"`
}

// ---------------------------------------------------------------------------
// 1. Single-Threaded Verification (Verify)
// ---------------------------------------------------------------------------

func BenchmarkVerify_ZeroJWT_SingleThread(b *testing.B) {
	v := zerojwt.NewVerifier(benchmarkSecret)
	st := v.NewScratch()
	now := time.Now().Unix()
	tok := v.SignClaims(nil, []byte("12345"), []byte("golden_ember_1"), now, now+3600)
	var claims zerojwt.Claims

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		now := time.Now().Unix()
		if err := v.VerifyWithScratch(tok, now, &claims, st); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify_ZeroJWT_Pool(b *testing.B) {
	v := zerojwt.NewVerifier(benchmarkSecret)
	now := time.Now().Unix()
	tok := v.SignClaims(nil, []byte("12345"), []byte("golden_ember_1"), now, now+3600)
	var claims zerojwt.Claims

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		now := time.Now().Unix()
		if err := v.Verify(tok, now, &claims); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify_Kataras(b *testing.B) {
	now := time.Now().Unix()
	claimsIn := katarasClaims{
		Sub:  "12345",
		User: "golden_ember_1",
		Iat:  now,
		Exp:  now + 3600,
	}
	tok, err := katarasjwt.Sign(katarasjwt.HS256, benchmarkSecret, claimsIn)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		verifiedToken, err := katarasjwt.Verify(katarasjwt.HS256, benchmarkSecret, tok)
		if err != nil {
			b.Fatal(err)
		}
		var claims katarasClaims
		if err := verifiedToken.Claims(&claims); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify_GolangJWT(b *testing.B) {
	now := time.Now().Unix()
	claimsIn := standardClaims{
		User: "golden_ember_1",
		RegisteredClaims: golangjwt.RegisteredClaims{
			Subject:   "12345",
			IssuedAt:  golangjwt.NewNumericDate(time.Unix(now, 0)),
			ExpiresAt: golangjwt.NewNumericDate(time.Unix(now+3600, 0)),
		},
	}
	tokObj := golangjwt.NewWithClaims(golangjwt.SigningMethodHS256, claimsIn)
	tokStr, err := tokObj.SignedString(benchmarkSecret)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var claims standardClaims
		t, err := golangjwt.ParseWithClaims(tokStr, &claims, func(token *golangjwt.Token) (interface{}, error) {
			return benchmarkSecret, nil
		})
		if err != nil || !t.Valid {
			b.Fatalf("validation failed: %v", err)
		}
	}
}

func BenchmarkVerify_JWX(b *testing.B) {
	now := time.Now().Unix()
	tokObj, err := jwxjwt.NewBuilder().
		Subject("12345").
		Claim("user", "golden_ember_1").
		IssuedAt(time.Unix(now, 0)).
		Expiration(time.Unix(now+3600, 0)).
		Build()
	if err != nil {
		b.Fatal(err)
	}
	signedTok, err := jwxjwt.Sign(tokObj, jwxjwt.WithKey(jwa.HS256, benchmarkSecret))
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parsed, err := jwxjwt.Parse(signedTok, jwxjwt.WithKey(jwa.HS256, benchmarkSecret), jwxjwt.WithValidate(true))
		if err != nil || parsed == nil {
			b.Fatalf("validation failed: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// 2. Parallel Multi-Core Verification (RunParallel)
// ---------------------------------------------------------------------------

func BenchmarkVerifyParallel_ZeroJWT(b *testing.B) {
	v := zerojwt.NewVerifier(benchmarkSecret)
	now := time.Now().Unix()
	tok := v.SignClaims(nil, []byte("12345"), []byte("golden_ember_1"), now, now+3600)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var claims zerojwt.Claims
		for pb.Next() {
			now := time.Now().Unix()
			if err := v.Verify(tok, now, &claims); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkVerifyParallel_Kataras(b *testing.B) {
	now := time.Now().Unix()
	claimsIn := katarasClaims{
		Sub:  "12345",
		User: "golden_ember_1",
		Iat:  now,
		Exp:  now + 3600,
	}
	tok, err := katarasjwt.Sign(katarasjwt.HS256, benchmarkSecret, claimsIn)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			verifiedToken, err := katarasjwt.Verify(katarasjwt.HS256, benchmarkSecret, tok)
			if err != nil {
				b.Fatal(err)
			}
			var claims katarasClaims
			if err := verifiedToken.Claims(&claims); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkVerifyParallel_GolangJWT(b *testing.B) {
	now := time.Now().Unix()
	claimsIn := standardClaims{
		User: "golden_ember_1",
		RegisteredClaims: golangjwt.RegisteredClaims{
			Subject:   "12345",
			IssuedAt:  golangjwt.NewNumericDate(time.Unix(now, 0)),
			ExpiresAt: golangjwt.NewNumericDate(time.Unix(now+3600, 0)),
		},
	}
	tokObj := golangjwt.NewWithClaims(golangjwt.SigningMethodHS256, claimsIn)
	tokStr, err := tokObj.SignedString(benchmarkSecret)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			var claims standardClaims
			t, err := golangjwt.ParseWithClaims(tokStr, &claims, func(token *golangjwt.Token) (interface{}, error) {
				return benchmarkSecret, nil
			})
			if err != nil || !t.Valid {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkVerifyParallel_JWX(b *testing.B) {
	now := time.Now().Unix()
	tokObj, err := jwxjwt.NewBuilder().
		Subject("12345").
		Claim("user", "golden_ember_1").
		IssuedAt(time.Unix(now, 0)).
		Expiration(time.Unix(now+3600, 0)).
		Build()
	if err != nil {
		b.Fatal(err)
	}
	signedTok, err := jwxjwt.Sign(tokObj, jwxjwt.WithKey(jwa.HS256, benchmarkSecret))
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			parsed, err := jwxjwt.Parse(signedTok, jwxjwt.WithKey(jwa.HS256, benchmarkSecret), jwxjwt.WithValidate(true))
			if err != nil || parsed == nil {
				b.Fatal(err)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// 3. Token Signing (Sign)
// ---------------------------------------------------------------------------

func BenchmarkSign_ZeroJWT_SignClaims(b *testing.B) {
	v := zerojwt.NewVerifier(benchmarkSecret)
	now := time.Now().Unix()
	sub := []byte("12345")
	user := []byte("golden_ember_1")
	var dst [512]byte

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = v.SignClaims(dst[:0], sub, user, now, now+3600)
	}
}

func BenchmarkSign_ZeroJWT_SignBuilder(b *testing.B) {
	v := zerojwt.NewVerifier(benchmarkSecret)
	now := time.Now().Unix()
	sub := []byte("12345")
	var dst [512]byte

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sb := v.NewSigner(dst[:0])
		sb.SetSubject(sub).
			SetClaimString("user", "golden_ember_1").
			SetIssuedAt(now).
			SetExpiresAt(now + 3600)
		if _, err := sb.Sign(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign_Kataras(b *testing.B) {
	now := time.Now().Unix()
	claims := katarasClaims{
		Sub:  "12345",
		User: "golden_ember_1",
		Iat:  now,
		Exp:  now + 3600,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := katarasjwt.Sign(katarasjwt.HS256, benchmarkSecret, claims)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign_GolangJWT(b *testing.B) {
	now := time.Now().Unix()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		claims := standardClaims{
			User: "golden_ember_1",
			RegisteredClaims: golangjwt.RegisteredClaims{
				Subject:   "12345",
				IssuedAt:  golangjwt.NewNumericDate(time.Unix(now, 0)),
				ExpiresAt: golangjwt.NewNumericDate(time.Unix(now+3600, 0)),
			},
		}
		tokObj := golangjwt.NewWithClaims(golangjwt.SigningMethodHS256, claims)
		_, err := tokObj.SignedString(benchmarkSecret)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSign_JWX(b *testing.B) {
	now := time.Now().Unix()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tokObj, err := jwxjwt.NewBuilder().
			Subject("12345").
			Claim("user", "golden_ember_1").
			IssuedAt(time.Unix(now, 0)).
			Expiration(time.Unix(now+3600, 0)).
			Build()
		if err != nil {
			b.Fatal(err)
		}
		_, err = jwxjwt.Sign(tokObj, jwxjwt.WithKey(jwa.HS256, benchmarkSecret))
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestCompetitorsCompatibility(t *testing.T) {
	now := time.Now().Unix()
	v := zerojwt.NewVerifier(benchmarkSecret)
	tokZero := v.SignClaims(nil, []byte("12345"), []byte("golden_ember_1"), now, now+3600)

	// Verify zerojwt token with zerojwt
	var claimsZero zerojwt.Claims
	if err := v.Verify(tokZero, now, &claimsZero); err != nil {
		t.Fatalf("zerojwt verify failed: %v", err)
	}
	if string(claimsZero.Subject()) != "12345" || string(claimsZero.Username()) != "golden_ember_1" {
		t.Fatalf("unexpected claims from zerojwt: sub=%s user=%s", claimsZero.Subject(), claimsZero.Username())
	}

	// Verify zerojwt token with golang-jwt
	tokenParsed, err := golangjwt.ParseWithClaims(string(tokZero), &standardClaims{}, func(t *golangjwt.Token) (interface{}, error) {
		return benchmarkSecret, nil
	})
	if err != nil || !tokenParsed.Valid {
		t.Fatalf("golang-jwt failed to parse zerojwt token: %v", err)
	}

	// Verify zerojwt token with kataras
	verifiedKataras, err := katarasjwt.Verify(katarasjwt.HS256, benchmarkSecret, tokZero)
	if err != nil {
		t.Fatalf("kataras failed to verify zerojwt token: %v", err)
	}
	var kc katarasClaims
	if err := verifiedKataras.Claims(&kc); err != nil || kc.Sub != "12345" {
		t.Fatalf("kataras claims mismatch: %v, sub=%s", err, kc.Sub)
	}

	// Verify zerojwt token with jwx
	tokJwx, err := jwxjwt.Parse(tokZero, jwxjwt.WithKey(jwa.HS256, benchmarkSecret), jwxjwt.WithValidate(true))
	if err != nil {
		t.Fatalf("jwx failed to parse zerojwt token: %v", err)
	}
	if tokJwx.Subject() != "12345" {
		t.Fatalf("jwx claims mismatch: sub=%s", tokJwx.Subject())
	}
}
