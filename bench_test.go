package zerojwt

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func BenchmarkVerifyConcurrentPool(b *testing.B) {
	v := NewVerifier([]byte("twelve-dollar-challenge"))
	now := time.Now().Unix()
	tok := v.SignClaims(nil, []byte("12345"), []byte("golden_ember_1"), now, now+3600)
	var claims Claims

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := v.Verify(tok, now, &claims); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifySingleThreadScratch(b *testing.B) {
	v := NewVerifier([]byte("twelve-dollar-challenge"))
	st := v.NewScratch()
	now := time.Now().Unix()
	tok := v.SignClaims(nil, []byte("12345"), []byte("golden_ember_1"), now, now+3600)
	var claims Claims

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := v.VerifyWithScratch(tok, now, &claims, st); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyParallel(b *testing.B) {
	v := NewVerifier([]byte("twelve-dollar-challenge"))
	now := time.Now().Unix()
	tok := v.SignClaims(nil, []byte("12345"), []byte("golden_ember_1"), now, now+3600)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var claims Claims
		for pb.Next() {
			if err := v.Verify(tok, now, &claims); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkSignClaims(b *testing.B) {
	v := NewVerifier([]byte("twelve-dollar-challenge"))
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

func BenchmarkSignBuilder(b *testing.B) {
	v := NewVerifier([]byte("twelve-dollar-challenge"))
	now := time.Now().Unix()
	sub := []byte("12345")
	var dst [512]byte

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sb := v.NewSigner(dst[:0])
		sb.SetSubject(sub).
			SetClaimInt("tenant_id", 42).
			SetClaimString("role", "admin").
			SetExpiresAt(now + 3600)
		if _, err := sb.Sign(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyEd25519(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	v := NewEd25519Verifier(pub, priv, Options{})
	now := time.Now().Unix()
	tok := v.SignClaims(nil, []byte("12345"), []byte("golden_ember_1"), now, now+3600)
	var claims Claims

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := v.Verify(tok, now, &claims); err != nil {
			b.Fatal(err)
		}
	}
}
