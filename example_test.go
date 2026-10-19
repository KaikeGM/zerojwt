package zerojwt_test

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/KaikeGM/zerojwt"
)

// ExampleVerifier_Verify demonstrates token verification with zero heap allocations,
// extracting standard claims, and checking sentinel errors using errors.Is.
func ExampleVerifier_Verify() {
	secret := []byte("super-secret-key-32-bytes-long!!")
	verifier := zerojwt.NewVerifier(secret)
	now := int64(1700000000)

	// Issue a valid token into a stack-allocated buffer (0 allocs/op)
	var tokBuf [512]byte
	token := verifier.SignClaims(tokBuf[:0], []byte("user_123"), []byte("alice"), now, now+3600)

	// Verify token into stack-allocated Claims
	var claims zerojwt.Claims
	if err := verifier.Verify(token, now, &claims); err != nil {
		switch {
		case errors.Is(err, zerojwt.ErrExpiredToken):
			fmt.Println("Token is expired")
		case errors.Is(err, zerojwt.ErrInvalidSignature):
			fmt.Println("Invalid signature")
		default:
			fmt.Printf("Validation error: %v\n", err)
		}
		return
	}

	fmt.Printf("Authenticated: %s (%s)\n", claims.Username(), claims.Subject())

	// Verifying an expired token triggers ErrExpiredToken
	err := verifier.Verify(token, now+7200, &claims)
	if errors.Is(err, zerojwt.ErrExpiredToken) {
		fmt.Println("Detected expired token successfully")
	}

	// Output:
	// Authenticated: alice (user_123)
	// Detected expired token successfully
}

// ExampleVerifier_NewSigner demonstrates using the fluent SignBuilder to compose
// and sign a JWT with custom claims entirely on the stack with 0 heap allocations.
func ExampleVerifier_NewSigner() {
	secret := []byte("super-secret-key-32-bytes-long!!")
	verifier := zerojwt.NewVerifier(secret)
	now := int64(1700000000)

	var tokBuf [512]byte
	b := verifier.NewSigner(tokBuf[:0])
	b.SetSubject([]byte("user_456")).
		SetUsername([]byte("bob")).
		SetIssuer([]byte("auth.service")).
		SetAudience([]byte("api.service")).
		SetClaimString("role", "admin").
		SetClaimInt("tenant_id", 42).
		SetClaimBool("mfa", true).
		SetExpiresAt(now + 3600)

	token, err := b.Sign()
	if err != nil {
		fmt.Printf("Sign error: %v\n", err)
		return
	}

	var claims zerojwt.Claims
	if err := verifier.Verify(token, now, &claims); err != nil {
		fmt.Printf("Verify error: %v\n", err)
		return
	}

	fmt.Printf("Subject: %s\n", claims.Subject())
	fmt.Printf("Username: %s\n", claims.Username())
	fmt.Printf("HasExp: %t\n", claims.HasExp)

	// Output:
	// Subject: user_456
	// Username: bob
	// HasExp: true
}

// ExampleNewEd25519Verifier demonstrates an asymmetric microservices architecture where
// the authentication authority signs with an Ed25519 private key, and consuming
// microservices verify tokens using only the 32-byte public key (privKey = nil).
func ExampleNewEd25519Verifier() {
	// In production, keys are loaded from secure config/vault.
	// We generate an Ed25519 keypair for demonstration:
	pubKey, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		fmt.Printf("Key generation error: %v\n", err)
		return
	}

	now := int64(1700000000)

	// 1. Authentication Server: initialized with both pubKey and privKey to sign tokens.
	authServer := zerojwt.NewEd25519Verifier(pubKey, privKey, zerojwt.Options{
		ExpectedIssuer: "auth.internal",
	})

	var tokBuf [512]byte
	token := authServer.SignClaims(tokBuf[:0], []byte("srv_99"), []byte("payment-worker"), now, now+1800)

	// 2. Client Microservice: initialized with public key ONLY (privKey is nil).
	// This ensures the microservice can verify tokens, but cannot forge or issue them.
	microserviceVerifier := zerojwt.NewEd25519Verifier(pubKey, nil, zerojwt.Options{
		ExpectedIssuer: "auth.internal",
	})

	var claims zerojwt.Claims
	if err := microserviceVerifier.Verify(token, now, &claims); err != nil {
		fmt.Printf("Microservice verification failed: %v\n", err)
		return
	}

	fmt.Printf("Microservice verified token for %s (issuer valid: %t)\n", claims.Username(), claims.HasIss)

	// Output:
	// Microservice verified token for payment-worker (issuer valid: true)
}

// ExampleVerifier_VerifyCustom demonstrates inspecting arbitrary custom JSON attributes
// and claims directly from the verified payload buffer in 0 allocations.
func ExampleVerifier_VerifyCustom() {
	secret := []byte("super-secret-key-32-bytes-long!!")
	verifier := zerojwt.NewVerifier(secret)
	now := int64(1700000000)

	var tokBuf [512]byte
	b := verifier.NewSigner(tokBuf[:0])
	b.SetSubject([]byte("user_789")).
		SetClaimString("department", "engineering").
		SetClaimInt("clearance_level", 5).
		SetExpiresAt(now + 3600)

	token, _ := b.Sign()

	var dept string
	var clearance int64

	// Verify and extract arbitrary claims in a single pass with 0 heap allocations
	err := verifier.VerifyCustom(token, now, func(key, val []byte, isStr bool) bool {
		switch string(key) {
		case "department":
			dept = string(val)
		case "clearance_level":
			clearance, _ = zerojwt.ParsePositiveInt(val)
		}
		return true // continue scanning
	})

	if err != nil {
		fmt.Printf("VerifyCustom error: %v\n", err)
		return
	}

	fmt.Printf("Department: %s, Clearance Level: %d\n", dept, clearance)

	// Output:
	// Department: engineering, Clearance Level: 5
}

// ExampleVerifier_ProtectFunc demonstrates wrapping an HTTP handler with ultra-low latency
// and 0 heap allocations per authenticated request.
func ExampleVerifier_ProtectFunc() {
	secret := []byte("super-secret-key-32-bytes-long!!")
	verifier := zerojwt.NewVerifier(secret)
	now := time.Now().Unix()

	// Create an authenticated HTTP handler receiving stack-allocated *Claims
	handler := verifier.ProtectFunc(func(w http.ResponseWriter, r *http.Request, claims *zerojwt.Claims) {
		fmt.Fprintf(w, "Hello, %s!", claims.Username())
	})

	// Sign a test token
	var tokBuf [512]byte
	token := verifier.SignClaims(tokBuf[:0], []byte("u1"), []byte("charlie"), now, now+3600)

	// Simulate an HTTP request with the Bearer token
	req := httptest.NewRequest("GET", "/profile", nil)
	req.Header.Set("Authorization", "Bearer "+string(token))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	fmt.Printf("Status: %d, Body: %s\n", rec.Code, rec.Body.String())

	// Output:
	// Status: 200, Body: Hello, charlie!
}
