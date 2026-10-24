package zerojwt

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestForwardAuthHandler(t *testing.T) {
	secret := []byte("secret-number-1-must-be-at-least-32-bytes!!")
	v, err := New(secret)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	tokValid, err := v.SignClaims(nil, StandardClaims{
		ExpiresAt: now + 3600,
		Subject:   "sub-12345",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Token with username
	signer := v.NewSigner(nil)
	signer.SetSubject("user-id-999")
	signer.SetUsername("octocat")
	signer.SetExpiresAt(now + 3600)
	tokWithUser, err := signer.Sign()
	if err != nil {
		t.Fatal(err)
	}

	// 1. Standard Bearer token authentication
	handler := v.ForwardAuthHandler()

	req := httptest.NewRequest("GET", "/auth", nil)
	req.Header.Set("Authorization", "Bearer "+string(tokValid))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
	if rec.Header().Get("X-Auth-User") != "sub-12345" {
		t.Fatalf("expected X-Auth-User=sub-12345, got %q", rec.Header().Get("X-Auth-User"))
	}
	if rec.Header().Get("X-Auth-Sub") != "sub-12345" {
		t.Fatalf("expected X-Auth-Sub=sub-12345, got %q", rec.Header().Get("X-Auth-Sub"))
	}

	// 2. Token with username
	req = httptest.NewRequest("GET", "/auth", nil)
	req.Header.Set("Authorization", "Bearer "+string(tokWithUser))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
	if rec.Header().Get("X-Auth-User") != "octocat" {
		t.Fatalf("expected X-Auth-User=octocat, got %q", rec.Header().Get("X-Auth-User"))
	}
	if rec.Header().Get("X-Auth-Sub") != "user-id-999" {
		t.Fatalf("expected X-Auth-Sub=user-id-999, got %q", rec.Header().Get("X-Auth-Sub"))
	}

	// 3. Missing Authorization header -> 401
	req = httptest.NewRequest("GET", "/auth", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for missing auth, got %d", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") != `Bearer error="unauthorized"` {
		t.Fatalf("expected WWW-Authenticate header, got %q", rec.Header().Get("WWW-Authenticate"))
	}

	// 4. Invalid / expired Bearer token -> 401
	req = httptest.NewRequest("GET", "/auth", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.signature")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for invalid token, got %d", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") != `Bearer error="unauthorized"` {
		t.Fatalf("expected WWW-Authenticate header, got %q", rec.Header().Get("WWW-Authenticate"))
	}

	// 5. Custom header extraction
	customHeaderHandler := v.ForwardAuthHandler(ForwardAuthOptions{
		CustomHeader: "X-Forwarded-Token",
		UserHeader:   "X-Forwarded-User",
		SubHeader:    "X-Forwarded-Sub",
		PopulateHeaders: func(w http.ResponseWriter, r *http.Request, claims *Claims) {
			w.Header().Set("X-Custom-Scope", "admin")
		},
	})

	req = httptest.NewRequest("GET", "/auth", nil)
	req.Header.Set("X-Forwarded-Token", string(tokValid))
	rec = httptest.NewRecorder()
	customHeaderHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK with custom header, got %d", rec.Code)
	}
	if rec.Header().Get("X-Forwarded-User") != "sub-12345" {
		t.Fatalf("expected X-Forwarded-User=sub-12345, got %q", rec.Header().Get("X-Forwarded-User"))
	}
	if rec.Header().Get("X-Custom-Scope") != "admin" {
		t.Fatalf("expected X-Custom-Scope=admin, got %q", rec.Header().Get("X-Custom-Scope"))
	}

	// Invalid custom header token -> 401
	req = httptest.NewRequest("GET", "/auth", nil)
	req.Header.Set("X-Forwarded-Token", "invalid")
	rec = httptest.NewRecorder()
	customHeaderHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid custom header token, got %d", rec.Code)
	}

	// 6. Cookie extraction
	cookieHandler := v.ForwardAuthHandler(ForwardAuthOptions{
		CookieName: "auth_jwt",
		UserHeader: "-",
		SubHeader:  "-",
	})

	req = httptest.NewRequest("GET", "/auth", nil)
	req.AddCookie(&http.Cookie{Name: "auth_jwt", Value: string(tokValid)})
	rec = httptest.NewRecorder()
	cookieHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK with cookie, got %d", rec.Code)
	}
	if rec.Header().Get("X-Auth-User") != "" || rec.Header().Get("X-Auth-Sub") != "" {
		t.Fatalf("headers should be suppressed when '-' is specified")
	}

	// Missing cookie -> 401
	req = httptest.NewRequest("GET", "/auth", nil)
	rec = httptest.NewRecorder()
	cookieHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing cookie, got %d", rec.Code)
	}

	// Invalid token in cookie -> 401
	req = httptest.NewRequest("GET", "/auth", nil)
	req.AddCookie(&http.Cookie{Name: "auth_jwt", Value: "invalid"})
	rec = httptest.NewRecorder()
	cookieHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid cookie token, got %d", rec.Code)
	}
}

func BenchmarkForwardAuthHandler(b *testing.B) {
	secret := []byte("secret-number-1-must-be-at-least-32-bytes!!")
	v, err := New(secret)
	if err != nil {
		b.Fatal(err)
	}

	now := time.Now().Unix()
	tokValid, err := v.SignClaims(nil, StandardClaims{
		ExpiresAt: now + 3600,
		Subject:   "sub-benchmark",
	})
	if err != nil {
		b.Fatal(err)
	}

	handler := v.ForwardAuthHandler()
	authVal := "Bearer " + string(tokValid)

	req := httptest.NewRequest("GET", "/auth", nil)
	req.Header.Set("Authorization", authVal)
	rec := httptest.NewRecorder()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.ServeHTTP(rec, req)
		rec.Body.Reset()
	}
}

func TestContextClaimHelpers(t *testing.T) {
	ctx := context.Background()
	if c := FromContext(ctx); c != nil {
		t.Errorf("expected nil claims from empty context, got %v", c)
	}
}

func TestForwardAuthHandler_CRLFAndHeaderInjection(t *testing.T) {
	secret := []byte("secret-number-1-must-be-at-least-32-bytes!!")
	v, err := New(secret)
	if err != nil {
		t.Fatal(err)
	}
	handler := v.ForwardAuthHandler()

	// 1. CRLF in Username claim
	signer1 := v.NewSigner(nil)
	signer1.SetSubject("normal-sub")
	signer1.SetUsername("admin\r\nX-Injected: evil")
	signer1.SetExpiresAt(time.Now().Unix() + 3600)
	tok1, err := signer1.Sign()
	if err != nil {
		t.Fatal(err)
	}

	req1 := httptest.NewRequest("GET", "/auth", nil)
	req1.Header.Set("Authorization", "Bearer "+string(tok1))
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for CRLF in username, got %d", rec1.Code)
	}

	// 2. CRLF in Subject claim
	signer2 := v.NewSigner(nil)
	signer2.SetSubject("evil\nSet-Cookie: session=pwned")
	signer2.SetExpiresAt(time.Now().Unix() + 3600)
	tok2, err := signer2.Sign()
	if err != nil {
		t.Fatal(err)
	}

	req2 := httptest.NewRequest("GET", "/auth", nil)
	req2.Header.Set("Authorization", "Bearer "+string(tok2))
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for CRLF in subject, got %d", rec2.Code)
	}

	// 3. Control byte \x7f (DEL) and \x00 in Subject claim
	signer3 := v.NewSigner(nil)
	signer3.SetSubject("evil\x7fuser")
	signer3.SetExpiresAt(time.Now().Unix() + 3600)
	tok3, err := signer3.Sign()
	if err != nil {
		t.Fatal(err)
	}

	req3 := httptest.NewRequest("GET", "/auth", nil)
	req3.Header.Set("Authorization", "Bearer "+string(tok3))
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for DEL in subject, got %d", rec3.Code)
	}

	// 4. hasHTTPHeaderControlByte direct tests
	if !hasHTTPHeaderControlByte([]byte("test\r\n")) {
		t.Error("expected true for CRLF")
	}
	if !hasHTTPHeaderControlByte([]byte("test\x00")) {
		t.Error("expected true for null byte")
	}
	if !hasHTTPHeaderControlByte([]byte("test\x7f")) {
		t.Error("expected true for DEL")
	}
	if hasHTTPHeaderControlByte([]byte("clean-user_123.valid")) {
		t.Error("expected false for clean string")
	}
}
