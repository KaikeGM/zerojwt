package zerojwt_test

import (
	"bytes"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	zerojwt "github.com/KaikeGM/zerojwt/v2"
)

func TestStudyZeroAllocations(t *testing.T) {
	if zerojwt.RaceDetectorEnabled {
		t.Skip("skipping zero-allocations verification under race detector")
	}

	secret := bytes.Repeat([]byte("s"), 32)
	v, err := zerojwt.New(secret)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	var dst [512]byte
	var iov [2][]byte
	payload := []byte(`{"sub":"user-12345","username":"alice","iat":1700000000,"exp":1700003600}`)

	// 1. SignToIOV: 0 allocs
	signIOVAllocs := testing.AllocsPerRun(100, func() {
		err := v.SignToIOV(dst[:0], payload, &iov)
		if err != nil {
			t.Fatal(err)
		}
	})
	if signIOVAllocs != 0 {
		t.Fatalf("expected 0 allocs in SignToIOV, got %v", signIOVAllocs)
	}

	// 2. SignClaimsToIOV: 0 allocs
	claimsIn := zerojwt.StandardClaims{
		Subject:   "user-12345",
		Username:  "alice",
		IssuedAt:  now,
		ExpiresAt: now + 3600,
	}
	signClaimsIOVAllocs := testing.AllocsPerRun(100, func() {
		err := v.SignClaimsToIOV(dst[:0], claimsIn, &iov)
		if err != nil {
			t.Fatal(err)
		}
	})
	if signClaimsIOVAllocs != 0 {
		t.Fatalf("expected 0 allocs in SignClaimsToIOV, got %v", signClaimsIOVAllocs)
	}

	// 3. VerifySplit: 0 allocs
	var claimsOut zerojwt.Claims
	verifySplitAllocs := testing.AllocsPerRun(100, func() {
		err := v.VerifySplit(iov[0], iov[1], now, &claimsOut)
		if err != nil {
			t.Fatal(err)
		}
	})
	if verifySplitAllocs != 0 {
		t.Fatalf("expected 0 allocs in VerifySplit, got %v", verifySplitAllocs)
	}

	// 4. WorkerScratchGroup VerifyWithScratch: 0 allocs
	group := zerojwt.NewWorkerScratchGroup(v, 4)
	workerScratch := group.For(0)
	tokenBytes := append(append([]byte(nil), iov[0]...), iov[1]...)

	workerVerifyAllocs := testing.AllocsPerRun(100, func() {
		err := v.VerifyWithScratch(tokenBytes, now, &claimsOut, workerScratch)
		if err != nil {
			t.Fatal(err)
		}
	})
	if workerVerifyAllocs != 0 {
		t.Fatalf("expected 0 allocs in WorkerScratchGroup Verify, got %v", workerVerifyAllocs)
	}
}

func BenchmarkSignHS256_Standard(b *testing.B) {
	secret := bytes.Repeat([]byte("s"), 32)
	v, _ := zerojwt.New(secret)
	payload := []byte(`{"sub":"user-12345","username":"alice","iat":1700000000,"exp":1700003600}`)
	var dst [512]byte

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = v.Sign(dst[:0], payload)
	}
}

func BenchmarkSignHS256_SignToIOV(b *testing.B) {
	secret := bytes.Repeat([]byte("s"), 32)
	v, _ := zerojwt.New(secret)
	payload := []byte(`{"sub":"user-12345","username":"alice","iat":1700000000,"exp":1700003600}`)
	var dst [512]byte
	var iov [2][]byte

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = v.SignToIOV(dst[:0], payload, &iov)
	}
}

func BenchmarkVerifyParallel_SyncPool(b *testing.B) {
	secret := bytes.Repeat([]byte("s"), 32)
	v, _ := zerojwt.New(secret)
	now := time.Now().Unix()
	tok, _ := v.Sign(nil, []byte(fmt.Sprintf(`{"sub":"user-12345","exp":%d}`, now+3600)))

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var claims zerojwt.Claims
		for pb.Next() {
			if err := v.Verify(tok, now, &claims); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkVerifyParallel_WorkerScratchGroup(b *testing.B) {
	secret := bytes.Repeat([]byte("s"), 32)
	v, _ := zerojwt.New(secret)
	now := time.Now().Unix()
	tok, _ := v.Sign(nil, []byte(fmt.Sprintf(`{"sub":"user-12345","exp":%d}`, now+3600)))

	numWorkers := 32
	group := zerojwt.NewWorkerScratchGroup(v, numWorkers)
	var workerSeq uint64

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		wid := int(atomic.AddUint64(&workerSeq, 1) - 1)
		sc := group.For(wid)
		var claims zerojwt.Claims
		for pb.Next() {
			if err := v.VerifyWithScratch(tok, now, &claims, sc); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkVerifyHS256_Contiguous(b *testing.B) {
	secret := bytes.Repeat([]byte("s"), 32)
	v, _ := zerojwt.New(secret)
	now := time.Now().Unix()
	tok, _ := v.Sign(nil, []byte(fmt.Sprintf(`{"sub":"user-12345","exp":%d}`, now+3600)))
	var claims zerojwt.Claims

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := v.Verify(tok, now, &claims); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyHS256_VerifySplit(b *testing.B) {
	secret := bytes.Repeat([]byte("s"), 32)
	v, _ := zerojwt.New(secret)
	now := time.Now().Unix()
	var dst [512]byte
	var iov [2][]byte
	_ = v.SignToIOV(dst[:0], []byte(fmt.Sprintf(`{"sub":"user-12345","exp":%d}`, now+3600)), &iov)
	var claims zerojwt.Claims

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := v.VerifySplit(iov[0], iov[1], now, &claims); err != nil {
			b.Fatal(err)
		}
	}
}
