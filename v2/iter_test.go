package zerojwt_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	zerojwt "github.com/KaikeGM/zerojwt/v2"
)

func TestArrayElements(t *testing.T) {
	raw := []byte(`["admin", "editor", "viewer"]`)
	var elems []string
	var isStrs []bool
	for elem, isStr := range zerojwt.ArrayElements(raw) {
		elems = append(elems, string(elem))
		isStrs = append(isStrs, isStr)
	}
	if len(elems) != 3 {
		t.Fatalf("expected 3 elements, got %d", len(elems))
	}
	expected := []string{"admin", "editor", "viewer"}
	for i, exp := range expected {
		if elems[i] != exp || !isStrs[i] {
			t.Fatalf("[%d] expected %q (str=true), got %q (str=%v)", i, exp, elems[i], isStrs[i])
		}
	}

	// Error handling
	var err error
	for range zerojwt.ArrayElements([]byte(`not_an_array`), &err) {
	}
	if !errors.Is(err, zerojwt.ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload on non-array, got %v", err)
	}

	err = nil
	for range zerojwt.ArrayElements([]byte(`["admin", `), &err) {
	}
	if !errors.Is(err, zerojwt.ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload on truncated array, got %v", err)
	}

	// Break early
	count := 0
	for range zerojwt.ArrayElements(raw) {
		count++
		if count == 2 {
			break
		}
	}
	if count != 2 {
		t.Fatalf("expected early break at count 2, got %d", count)
	}
}

func TestObjectPropsAndProperties(t *testing.T) {
	raw := []byte(`{"user":"bob","age":42,"active":true}`)

	// ObjectProps (key, val)
	propsMap := make(map[string]string)
	for k, v := range zerojwt.ObjectProps(raw) {
		propsMap[string(k)] = string(v)
	}
	if propsMap["user"] != "bob" || propsMap["age"] != "42" || propsMap["active"] != "true" {
		t.Fatalf("unexpected props: %v", propsMap)
	}

	// ObjectProperties (JSONProp)
	count := 0
	for prop := range zerojwt.ObjectProperties(raw) {
		count++
		if string(prop.Key) == "user" && (!prop.IsStr || string(prop.Val) != "bob") {
			t.Fatalf("expected user string 'bob', got %v", prop)
		}
	}
	if count != 3 {
		t.Fatalf("expected 3 properties, got %d", count)
	}

	// Errors
	var err error
	for range zerojwt.ObjectProps([]byte(`not_object`), &err) {
	}
	if !errors.Is(err, zerojwt.ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload on non-object, got %v", err)
	}

	err = nil
	for range zerojwt.ObjectProps([]byte(`{"unclosed`), &err) {
	}
	if !errors.Is(err, zerojwt.ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload on unclosed object, got %v", err)
	}

	err = nil
	for range zerojwt.ObjectProperties([]byte(`not_object`), &err) {
	}
	if !errors.Is(err, zerojwt.ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload on non-object, got %v", err)
	}

	err = nil
	for range zerojwt.ObjectProperties([]byte(`{"bad`), &err) {
	}
	if !errors.Is(err, zerojwt.ErrInvalidPayload) {
		t.Fatalf("expected ErrInvalidPayload on bad object, got %v", err)
	}

	// Break early
	c := 0
	for range zerojwt.ObjectProps(raw) {
		c++
		break
	}
	if c != 1 {
		t.Fatalf("expected break at 1, got %d", c)
	}

	c = 0
	for range zerojwt.ObjectProperties(raw) {
		c++
		break
	}
	if c != 1 {
		t.Fatalf("expected break at 1, got %d", c)
	}
}

func TestAtomicVerificationAndIteration(t *testing.T) {
	secret := bytes.Repeat([]byte("s"), 32)
	v, err := zerojwt.New(secret, zerojwt.Options{
		ExpectedIssuer:   "auth.zerojwt.io",
		ExpectedAudience: "api.zerojwt.io",
	})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()

	// 1. Create a valid token
	b := v.NewSigner(nil)
	b.SetSubject("user-12345")
	b.SetIssuer("auth.zerojwt.io")
	b.SetAudience("api.zerojwt.io")
	b.SetExpiresAt(now + 3600)
	b.SetClaimString("role", "admin")
	validTok, err := b.Sign()
	if err != nil {
		t.Fatal(err)
	}

	// VerifyAndIterate on valid token
	claimsSeen := make(map[string]string)
	err = v.VerifyAndIterate(validTok, now, func(k, val []byte, isStr bool) bool {
		claimsSeen[string(k)] = string(val)
		return true
	})
	if err != nil {
		t.Fatalf("VerifyAndIterate failed on valid token: %v", err)
	}
	if claimsSeen["role"] != "admin" || claimsSeen["sub"] != "user-12345" {
		t.Fatalf("expected claims to be populated, got: %v", claimsSeen)
	}

	// Iter iterator on valid token
	iterSeen := make(map[string]string)
	for prop, iterErr := range v.Iter(validTok, now) {
		if iterErr != nil {
			t.Fatalf("unexpected iter error: %v", iterErr)
		}
		iterSeen[string(prop.Key)] = string(prop.Val)
	}
	if iterSeen["role"] != "admin" || iterSeen["sub"] != "user-12345" {
		t.Fatalf("expected iter claims, got: %v", iterSeen)
	}

	// 2. ATOMICITY TEST: Expired token
	bExpired := v.NewSigner(nil)
	bExpired.SetSubject("hacker")
	bExpired.SetIssuer("auth.zerojwt.io")
	bExpired.SetAudience("api.zerojwt.io")
	bExpired.SetExpiresAt(now - 100) // expired!
	bExpired.SetClaimString("role", "superadmin")
	expiredTok, err := bExpired.Sign()
	if err != nil {
		t.Fatal(err)
	}

	calls := 0
	err = v.VerifyAndIterate(expiredTok, now, func(k, val []byte, isStr bool) bool {
		calls++
		return true
	})
	if !errors.Is(err, zerojwt.ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
	if calls != 0 {
		t.Fatalf("SECURITY VIOLATION: callback was called %d times for expired token!", calls)
	}

	// Iter atomicity check for expired token
	iterCalls := 0
	var gotIterErr error
	for _, itErr := range v.Iter(expiredTok, now) {
		iterCalls++
		gotIterErr = itErr
	}
	if !errors.Is(gotIterErr, zerojwt.ErrTokenExpired) {
		t.Fatalf("expected Iter to yield ErrTokenExpired, got %v", gotIterErr)
	}
	if iterCalls != 1 {
		t.Fatalf("expected Iter to yield exactly 1 error item, got %d yields", iterCalls)
	}

	// 3. ATOMICITY TEST: Forged signature
	forgedTok := append([]byte(nil), validTok...)
	forgedTok[len(forgedTok)-2] ^= 0xFF // corrupt signature
	calls = 0
	err = v.VerifyAndIterate(forgedTok, now, func(k, val []byte, isStr bool) bool {
		calls++
		return true
	})
	if !errors.Is(err, zerojwt.ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
	if calls != 0 {
		t.Fatalf("SECURITY VIOLATION: callback was called %d times for forged signature!", calls)
	}

	// 4. ATOMICITY TEST: Mismatched audience
	bBadAud := v.NewSigner(nil)
	bBadAud.SetSubject("victim")
	bBadAud.SetIssuer("auth.zerojwt.io")
	bBadAud.SetAudience("other-service")
	bBadAud.SetExpiresAt(now + 3600)
	bBadAud.SetClaimString("secret", "classified")
	badAudTok, err := bBadAud.Sign()
	if err != nil {
		t.Fatal(err)
	}
	calls = 0
	err = v.VerifyAndIterate(badAudTok, now, func(k, val []byte, isStr bool) bool {
		calls++
		return true
	})
	if !errors.Is(err, zerojwt.ErrInvalidAudience) {
		t.Fatalf("expected ErrInvalidAudience, got %v", err)
	}
	if calls != 0 {
		t.Fatalf("SECURITY VIOLATION: callback was called %d times for mismatched audience!", calls)
	}

	// 5. ATOMICITY TEST: Token not valid yet (nbf)
	bFuture := v.NewSigner(nil)
	bFuture.SetSubject("victim")
	bFuture.SetIssuer("auth.zerojwt.io")
	bFuture.SetAudience("api.zerojwt.io")
	bFuture.SetNotBefore(now + 1000)
	bFuture.SetExpiresAt(now + 2000)
	bFuture.SetClaimString("secret", "classified")
	futureTok, err := bFuture.Sign()
	if err != nil {
		t.Fatal(err)
	}
	calls = 0
	err = v.VerifyAndIterate(futureTok, now, func(k, val []byte, isStr bool) bool {
		calls++
		return true
	})
	if !errors.Is(err, zerojwt.ErrTokenNotValidYet) {
		t.Fatalf("expected ErrTokenNotValidYet, got %v", err)
	}
	if calls != 0 {
		t.Fatalf("SECURITY VIOLATION: callback was called %d times for future nbf!", calls)
	}
}
