# ⚡ `zerojwt` — Ultra-Fast, Zero-Allocation Industrial JWT for Go

[![Go Reference](https://pkg.go.dev/badge/github.com/KaikeGM/zerojwt.svg)](https://pkg.go.dev/github.com/KaikeGM/zerojwt)
[![Go Report Card](https://goreportcard.com/badge/github.com/KaikeGM/zerojwt)](https://goreportcard.com/report/github.com/KaikeGM/zerojwt)
[![Coverage](https://img.shields.io/badge/coverage-100.0%25-brightgreen.svg)](https://github.com/KaikeGM/zerojwt)
[![Allocations](https://img.shields.io/badge/allocations-0_B%2Fop-blue.svg)](https://github.com/KaikeGM/zerojwt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`zerojwt` is a pure Go, zero-dependency library for signing and verifying **JSON Web Tokens (JWT / RFC 7519)** in **~185 ns/op (parallel) / ~400–640 ns/op (single-core)** with guaranteed **`0 B/op` and `0 allocs/op`** on critical execution paths.

Born out of **PR #48 (`go-gnet-kaikegm`)** in *The $12 Server Challenge* — where a single OS thread sustained **300,000 concurrent keep-alive connections** and **35,577 req/s** — `zerojwt` eliminates the reflection, `encoding/json` dynamic map allocations, and Garbage Collector (GC) pressure of traditional Go JWT packages while delivering complete, industrial-grade capabilities.

---

## 📑 Table of Contents

- [Benchmark Comparison](#-benchmark-comparison)
- [Key Features](#-key-features)
- [Architecture & Memory Model](#-architecture--memory-model)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Cryptographic Algorithms](#-cryptographic-algorithms)
  - [Symmetric: HS256, HS384, HS512](#1-symmetric-hmac-hs256-hs384-hs512)
  - [Asymmetric: EdDSA (Ed25519)](#2-asymmetric-eddsa-ed25519--rfc-8037)
  - [Asymmetric: ES256 (ECDSA P-256)](#3-asymmetric-es256-ecdsa-p-256--rfc-7518)
- [RFC 7519 Validation & Claims](#-rfc-7519-validation--claims)
  - [Clock Skew Tolerance (Leeway)](#clock-skew-tolerance-leeway)
  - [Issuer (iss) & Audience (aud) Validation](#issuer-iss--audience-aud-validation)
  - [JWT ID (jti) & Replay Prevention](#jwt-id-jti--replay-prevention)
  - [Dual Claims Structs: Claims vs ClaimsLarge](#dual-claims-structs-claims-vs-claimslarge)
- [Custom Claims & Fluent SignBuilder](#-custom-claims--fluent-signbuilder)
  - [Fluent SignBuilder (0 allocs/op)](#fluent-signbuilder-0-allocsop)
  - [Arbitrary Claims Inspection via VerifyCustom](#arbitrary-claims-inspection-via-verifycustom)
- [Zero-Downtime Key Rotation (kid)](#-zero-downtime-key-rotation-kid)
- [High-Speed HTTP Middlewares](#-high-speed-http-middlewares)
  - [ProtectFunc (0 allocs/op)](#1-protectfunc-fastest-zero-allocation)
  - [Standard net/http & Chi Middleware](#2-standard-nethttp--chi-middleware)
  - [Gin, Fiber & gnet Integration](#3-gin-fiber--gnet-integration)
- [Security & Compliance (FIPS / PCI-DSS)](#-security--compliance-fips--pci-dss)
- [Profile-Guided Optimization (PGO)](#-profile-guided-optimization-pgo)
- [API Reference](#-api-reference)
- [Sentinel Errors](#-sentinel-errors)
- [Testing, Fuzzing & Quality Assurance](#-testing-fuzzing--quality-assurance)
- [License](#-license)

---

## 🚀 Benchmark Comparison

Tested on an Intel(R) Core(TM) i5-1135G7 @ 2.40GHz (Linux amd64, Go 1.22):

| Library | Operations / sec | Latency | Memory / op | Allocs / op |
| :--- | :---: | :---: | :---: | :---: |
| **`zerojwt` (Parallel 8 CPUs)** | **~5,000,000 ops/s** | **~200 ns/op** | **`0 B/op`** | **`0 allocs/op`** |
| **`zerojwt` (Single Thread Scratch)** | **~1,560,000 ops/s** | **~638 ns/op** | **`0 B/op`** | **`0 allocs/op`** |
| **`zerojwt` (Concurrent Pool)** | **~1,510,000 ops/s** | **~658 ns/op** | **`0 B/op`** | **`0 allocs/op`** |
| **`zerojwt` (SignClaims)** | **~2,470,000 ops/s** | **~404 ns/op** | **`0 B/op`** | **`0 allocs/op`** |
| **`zerojwt` (SignBuilder)** | **~2,260,000 ops/s** | **~441 ns/op** | **`0 B/op`** | **`0 allocs/op`** |
| `kataras/jwt` | ~450,000 ops/s | ~2,200 ns/op | ~896 B/op | 14 allocs/op |
| `golang-jwt/jwt/v5` | ~380,000 ops/s | ~2,600 ns/op | ~1,440 B/op | 26 allocs/op |
| `lestrrat-go/jwx/v2` | ~190,000 ops/s | ~5,200 ns/op | ~3,120 B/op | 48 allocs/op |

> **Key takeaway:** Traditional JWT libraries allocate between 14 and 48 objects on the heap per token validation, triggering constant garbage collector cycles under high loads (10k+ req/s). `zerojwt` performs **zero heap allocations**, allowing web gateways and event loops to handle maximum connection density with flat, predictable latencies.

---

## ✨ Key Features

1. **Strict 0 Allocations Guarantee:**
   - Both token signing and token verification operate completely without heap allocations (`0 B/op, 0 allocs/op`).
   - No `interface{}` unboxing, no `map[string]any` parsing, no reflection (`reflect`).

2. **Complete Cryptographic Algorithm Portfolio:**
   - **Symmetric:** `HS256`, `HS384`, `HS512` (HMAC with SHA-2 family).
   - **Asymmetric:** `EdDSA` (`Ed25519` / RFC 8037) and `ES256` (`ECDSA P-256` / RFC 7518).
   - Custom ASN.1 DER to IEEE P1363 fixed-width (64-byte $r \parallel s$) conversion implemented directly on stack buffers.

3. **Strict RFC 7519 / RFC 7515 Compliance:**
   - Configurable clock skew tolerance (`Leeway`).
   - Standard claims: `exp` (Expires At), `nbf` (Not Before), `iat` (Issued At), `iss` (Issuer), `aud` (Audience), `sub` (Subject), and `jti` (JWT ID).
   - Audience matching supports both single JSON strings (`"aud":"service"`) and JSON string arrays (`"aud":["svc-a","svc-b"]`) in zero allocations.
   - Enforces `typ: "JWT"` validation if present in the header.

4. **Zero-Copy In-Place Lexer (`scanner.go`):**
   - High-performance, streaming JSON tokenizer with precomputed 256-byte Lookup Tables (LUTs) for whitespace, delimiters, and hex conversion.
   - In-place string unescaping for standard escapes (`\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r`, `\t`) and full Unicode code points (`\uXXXX`), including UTF-16 surrogate pairs (`\uD800..\uDBFF` + `\uDC00..\uDFFF`).

5. **Multi-Key Credential Rotation (`kid`):**
   - Seamless key rotation with zero allocations using the `"kid"` header parameter.

6. **Stack-Allocated Fluent `SignBuilder`:**
   - Construct and sign custom payloads with arbitrary fields without allocating JSON strings or maps.

7. **FIPS / PCI-DSS Memory Sanitization:**
   - Optional `ZeroMemory` mode actively wipes cryptographic secrets and claims from scratch buffers via `memclr` before returning them to the pool.
   - `Verifier.Destroy()` safely zeroes internal master keys and HMAC state.

8. **Zero Third-Party Dependencies:**
   - Built exclusively with the Go standard library (`crypto/*`, `encoding/base64`, `sync`, `unsafe`).

---

## 🏛️ Architecture & Memory Model

`zerojwt` achieves zero heap allocations by replacing dynamic runtime allocations with **reusable Scratch workspaces**:

```
+-------------------------------------------------------------------------+
|                               Scratch                                   |
|                                                                         |
|  +--------------------+  +--------------------+  +-------------------+  |
|  |   hdrBuf [128]B    |  |  payloadBuf [1024]B|  |   sigBuf [64]B    |  |
|  +--------------------+  +--------------------+  +-------------------+  |
|  +--------------------+  +--------------------+  +-------------------+  |
|  |   sumBuf [64]B     |  |   derBuf [72]B     |  |  mac (hash.Hash)  |  |
|  +--------------------+  +--------------------+  +-------------------+  |
+-------------------------------------------------------------------------+
```

### Dual Concurrency Models

1. **Multithreaded Web Applications (`sync.Pool`):**
   Methods like `Verifier.Verify`, `Verifier.VerifyLarge`, `Verifier.VerifyBearer`, and `Verifier.Sign` automatically check out a `*Scratch` instance from an internal lock-free `sync.Pool` and return it upon completion.
2. **Single-Threaded Event Loops (`gnet` / `epoll` / Worker Pools):**
   Methods like `Verifier.VerifyWithScratch`, `Verifier.VerifyLargeWithScratch`, and `Verifier.SignWithScratch` accept a caller-managed `*Scratch` directly (e.g. pinned to the event loop's worker context), eliminating even the atomic overhead of `sync.Pool`.

---

## 📦 Installation

Requires Go 1.20 or higher (Go 1.22+ recommended for optimal PGO):

```bash
go get github.com/KaikeGM/zerojwt
```

---

## 🛠️ Quick Start

### Basic Signing and Verification

```go
package main

import (
	"fmt"
	"time"

	"github.com/KaikeGM/zerojwt"
)

func main() {
	secret := []byte("secret-key-must-be-at-least-32-bytes!!")
	verifier := zerojwt.NewVerifier(secret)
	now := time.Now().Unix()

	// 1. Sign a token into a stack buffer (0 allocs/op)
	var tokBuf [512]byte
	token := verifier.SignClaims(
		tokBuf[:0],
		[]byte("user_9876"), // sub
		[]byte("kaikegm"),   // username
		now,                 // iat
		now+3600,            // exp (1 hour)
	)

	fmt.Printf("Generated JWT: %s\n", token)

	// 2. Verify token into stack-allocated Claims (0 allocs/op)
	var claims zerojwt.Claims
	if err := verifier.Verify(token, now, &claims); err != nil {
		panic(err)
	}

	fmt.Printf("Authenticated: Subject=%s, Username=%s, ExpiresAt=%d\n",
		claims.Subject(), claims.Username(), claims.ExpiresAt)
}
```

---

## 🔐 Cryptographic Algorithms

### 1. Symmetric HMAC: HS256, HS384, HS512

Symmetric validation requires the same shared secret between issuer and validator.

```go
// HS256 (Default)
v256 := zerojwt.NewVerifier(secret)

// HS384
v384 := zerojwt.NewVerifierWithOptions(secret, zerojwt.Options{
	Algorithm: zerojwt.AlgHS384,
})

// HS512
v512 := zerojwt.NewVerifierWithOptions(secret, zerojwt.Options{
	Algorithm: zerojwt.AlgHS512,
})
```

---

### 2. Asymmetric: EdDSA (Ed25519 / RFC 8037)

Ed25519 provides ultra-fast asymmetric verification with 32-byte public keys and 64-byte signatures. Ideal for microservices architectures where internal services should only verify tokens without having the capability to issue them.

```go
import "crypto/ed25519"

// Generate keypair
pubKey, privKey, _ := ed25519.GenerateKey(nil)

// Authentication Server (Issues & Signs tokens)
authVerifier := zerojwt.NewEd25519Verifier(pubKey, privKey, zerojwt.Options{
	ExpectedIssuer: "https://auth.company.com",
})
token := authVerifier.SignClaims(tokBuf[:0], []byte("usr_1"), []byte("alice"), now, now+3600)

// Microservice / API Gateway (Verify-only: privKey is nil)
gatewayVerifier := zerojwt.NewEd25519Verifier(pubKey, nil, zerojwt.Options{
	ExpectedIssuer: "https://auth.company.com",
})
var claims zerojwt.Claims
if err := gatewayVerifier.Verify(token, now, &claims); err != nil {
	log.Fatalf("Invalid token: %v", err)
}
```

---

### 3. Asymmetric: ES256 (ECDSA P-256 / RFC 7518)

ES256 is widely used in enterprise OAuth 2.0 / OpenID Connect, mobile clients, and WebAuthn. `zerojwt` implements direct IEEE P1363 ($r \parallel s$) to ASN.1 DER conversion with zero heap allocations.

```go
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

// Generate P-256 keypair
privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
pubKey := &privKey.PublicKey

// Verifier with ES256
vES256 := zerojwt.NewES256Verifier(pubKey, privKey, zerojwt.Options{
	Leeway: 10 * time.Second,
})

token := vES256.Sign(tokBuf[:0], []byte(`{"sub":"usr_p256","exp":1893456000}`))
```

---

## 📋 RFC 7519 Validation & Claims

### Clock Skew Tolerance (Leeway)

In distributed systems, servers may experience slight NTP clock desynchronization. The `Leeway` option prevents premature token rejection:

```go
verifier := zerojwt.NewVerifierWithOptions(secret, zerojwt.Options{
	Leeway: 5 * time.Second, // Allows tokens up to 5s before nbf or 5s after exp
})
```

---

### Issuer (`iss`) & Audience (`aud`) Validation

When configured, `zerojwt` enforces that incoming tokens contain matching `iss` and `aud` claims:

```go
verifier := zerojwt.NewVerifierWithOptions(secret, zerojwt.Options{
	ExpectedIssuer:   "auth.enterprise.io",
	ExpectedAudience: "payments-api",
})
```

`zerojwt` natively validates `aud` claims declared as either a **single JSON string** or a **JSON array of strings**:
* Single: `"aud": "payments-api"`
* Array: `"aud": ["reporting-api", "payments-api", "admin-api"]`

Both variations are parsed and matched **in-place with 0 heap allocations**.

---

### JWT ID (`jti`) & Replay Prevention

The `jti` claim provides a unique nonce (e.g. UUID v4) to prevent replay attacks. `Claims` exposes `claims.JTI()` to check against in-memory revocation lists (such as a Bloom filter or synchronized cache):

```go
var claims zerojwt.Claims
if err := verifier.Verify(token, now, &claims); err != nil {
	return err
}

if revocationFilter.Contains(claims.JTI()) {
	return errors.New("token has been revoked")
}
```

---

### Dual Claims Structs: Claims vs ClaimsLarge

| Feature | `Claims` (Default) | `ClaimsLarge` |
| :--- | :---: | :---: |
| **Target Use Case** | High-density APIs, microservices | Enterprise tokens, long usernames/UUIDs |
| **Max Subject Length** | **64 bytes** | **256 bytes** |
| **Max Username Length** | **128 bytes** | **256 bytes** |
| **Max Issuer Length** | **64 bytes** | **256 bytes** |
| **Max Audience Length** | **64 bytes** | **256 bytes** |
| **Max JTI Length** | **36 bytes** (UUID) | **64 bytes** |
| **Memory Footprint** | Extremely compact | Slightly larger fixed stack size |
| **Verification Method** | `v.Verify(...)` | `v.VerifyLarge(...)` |

---

## 🛠️ Custom Claims & Fluent SignBuilder

### Fluent SignBuilder (0 allocs/op)

Build custom JWT payloads with arbitrary attributes without allocating `map[string]any` or strings:

```go
var tokBuf [1024]byte
builder := verifier.NewSigner(tokBuf[:0])

token, err := builder.
	SetSubject([]byte("usr_1001")).
	SetUsername([]byte("kaike")).
	SetIssuer([]byte("auth.company.com")).
	SetAudience([]byte("api.company.com")).
	SetJTI([]byte("9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d")).
	SetIssuedAt(now).
	SetExpiresAt(now + 7200).
	SetClaimString("role", "admin").
	SetClaimInt("tenant_id", 42).
	SetClaimBool("mfa_verified", true).
	SetClaimRawJSON("permissions", []byte(`["read:users","write:users"]`)).
	Sign()

if err != nil {
	panic(err)
}
```

---

### Arbitrary Claims Inspection via `VerifyCustom`

If your token contains arbitrary nested structures or custom attributes, use `VerifyCustom`. It validates signature and temporal claims (`exp`, `nbf`, `iss`, `aud`), and yields key-value slices directly from the verified buffer with **0 allocations**:

```go
err := verifier.VerifyCustom(token, now, func(key, val []byte, isStr bool) bool {
	switch string(key) {
	case "tenant_id":
		id, _ := zerojwt.ParsePositiveInt(val)
		fmt.Printf("Tenant: %d\n", id)
	case "permissions":
		// Traverse JSON array with 0 allocations
		arrBody, ok := zerojwt.TrimJSONArray(val)
		if ok {
			for len(arrBody) > 0 {
				elem, isStr, rest, ok := zerojwt.NextArrayElement(arrBody)
				if !ok {
					break
				}
				arrBody = rest
				fmt.Printf("Permission: %s (isStr=%v)\n", elem, isStr)
			}
		}
	}
	return true // continue scanning claims
})
```

---

## 🔄 Zero-Downtime Key Rotation (`kid`)

To rotate keys without invalidating existing sessions, register multiple keys with unique IDs:

```go
verifier := zerojwt.NewVerifierWithOptions(primarySecret, zerojwt.Options{
	Algorithm:   zerojwt.AlgHS256,
	ActiveKeyID: "key-2026-v2", // Embedded into new tokens
	Keys: []zerojwt.Key{
		{ID: "key-2025-v1", Secret: oldSecret},
		{ID: "key-2026-v2", Secret: primarySecret},
		{ID: "key-ed-v1", Ed25519Public: edPubKey},
		{ID: "key-es-v1", ECDSAPublic: ecPubKey},
	},
})
```

When validating, `zerojwt` extracts the `"kid"` claim from the header and uses the corresponding cryptographic key in $O(1)$ without heap allocations.

---

## 🌐 High-Speed HTTP Middlewares

### 1. `ProtectFunc` (Fastest, Zero-Allocation)

Passes a stack-allocated `*Claims` pointer directly to your handler, ensuring **`0 B/op` overhead** per HTTP request:

```go
http.HandleFunc("/api/me", verifier.ProtectFunc(func(w http.ResponseWriter, r *http.Request, claims *zerojwt.Claims) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"sub":"%s","user":"%s"}`, claims.Subject(), claims.Username())
}))
```

---

### 2. Standard `net/http` & Chi Middleware

Integrates seamlessly with Chi, Gorilla Mux, or standard Go routers:

```go
r := chi.NewRouter()
r.Use(verifier.Middleware)

r.Get("/api/dashboard", func(w http.ResponseWriter, r *http.Request) {
	claims, ok := zerojwt.ClaimsFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	fmt.Fprintf(w, "Welcome, user ID %d!", claims.SubjectID)
})
```

---

### 3. Gin, Fiber & gnet Integration

#### Gin
```go
func ZeroJWTGin(v *zerojwt.Verifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if len(auth) <= 7 {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		var claims zerojwt.Claims
		if err := v.VerifyBearer([]byte(auth), time.Now().Unix(), &claims); err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Set("claims", &claims)
		c.Next()
	}
}
```

#### gnet (Single-Thread Event Loop)
```go
type server struct {
	*gnet.BuiltinEventEngine
	verifier *zerojwt.Verifier
	scratch  *zerojwt.Scratch // 1 scratch per worker thread
}

func (s *server) OnTraffic(c gnet.Conn) gnet.Action {
	buf, _ := c.Next(-1)
	var claims zerojwt.Claims
	// Direct scratch verification: 0 allocations, 0 sync.Pool locks
	if err := s.verifier.VerifyWithScratch(buf, time.Now().Unix(), &claims, s.scratch); err != nil {
		c.Write([]byte("HTTP/1.1 401 Unauthorized\r\n\r\n"))
		return gnet.Close
	}
	// ...
	return gnet.None
}
```

---

## 🛡️ Security & Compliance (FIPS / PCI-DSS)

### Memory Sanitization (`ZeroMemory`)

In multi-tenant or regulated financial environments (PCI-DSS, HIPAA, FIPS), residual keys and user attributes must not linger in memory buffers.

Enable `ZeroMemory: true` to invoke Go's runtime `memclr` over all scratch buffers and claims before releasing them back to the pool:

```go
verifier := zerojwt.NewVerifierWithOptions(secret, zerojwt.Options{
	ZeroMemory: true,
})
```

To securely decommission a verifier and scrub master keys from RAM upon service shutdown:

```go
defer verifier.Destroy()
```

---

## ⚡ Profile-Guided Optimization (PGO)

`zerojwt` includes a factory `default.pgo` optimization profile captured under rigorous load testing.

When building your service with Go 1.20+, the Go compiler automatically discovers `default.pgo` and optimizes register allocation, hot branch predictions, and function inlining:

```bash
# Automatically applies default.pgo
go build -o my-service main.go
```

To verify PGO application during build:

```bash
go build -gcflags="-m=2" 2>&1 | grep "pgo inline"
```

---

## 📖 API Reference

### Verifier Constructors
- `NewVerifier(secret []byte) *Verifier`: Creates an HS256 verifier with default buffer limits (128B header, 1024B payload).
- `NewEd25519Verifier(pub ed25519.PublicKey, priv ed25519.PrivateKey, opts Options) *Verifier`: Creates an EdDSA (Ed25519) verifier.
- `NewES256Verifier(pub *ecdsa.PublicKey, priv *ecdsa.PrivateKey, opts Options) *Verifier`: Creates an ES256 (ECDSA P-256) verifier.
- `NewVerifierWithOptions(secret []byte, opts Options) *Verifier`: Creates a fully configured verifier.

### Verification Methods
- `Verify(tok []byte, nowUnix int64, out *Claims) error`: Validates token into standard `Claims`.
- `VerifyBearer(authHeader []byte, nowUnix int64, out *Claims) error`: Extracts `Bearer <token>` and validates.
- `VerifyWithScratch(tok []byte, nowUnix int64, out *Claims, st *Scratch) error`: Validates token using a caller-supplied `Scratch`.
- `VerifyLarge(tok []byte, nowUnix int64, out *ClaimsLarge) error`: Validates token into large-capacity `ClaimsLarge`.
- `VerifyLargeWithScratch(tok []byte, nowUnix int64, out *ClaimsLarge, st *Scratch) error`: Validates token into `ClaimsLarge` using caller-supplied `Scratch`.
- `VerifyCustom(tok []byte, nowUnix int64, onClaim func(key, val []byte, isStr bool) bool) error`: Validates signature and temporal claims, scanning arbitrary claims with zero allocations.

### Signing Methods
- `Sign(dst []byte, payloadJSON []byte) []byte`: Signs raw JSON payload using default buffers.
- `SignClaims(dst, sub, username []byte, iat, exp int64) []byte`: Signs standard claims directly into `dst`.
- `SignWithScratch(dst, payloadJSON []byte, st *Scratch) []byte`: Signs payload using caller-supplied `Scratch`.
- `NewSigner(dst []byte) SignBuilder`: Creates a fluent builder for custom claims backed by `sync.Pool`.
- `NewSignerWithScratch(dst []byte, st *Scratch) SignBuilder`: Creates a fluent builder using caller-supplied `Scratch`.

### Fast Lexer & Parser (`scanner.go`)
- `NextJSONProp(b []byte) (key, val []byte, isStr bool, rest []byte, ok bool)`: Extracts the next `"key": value` from a JSON object body in-place.
- `NextArrayElement(b []byte) (val []byte, isStr bool, rest []byte, ok bool)`: Extracts the next element from a JSON array body in-place.
- `TrimJSONObject(b []byte) ([]byte, bool)`: Strips whitespace and outer `{` and `}` braces.
- `TrimJSONArray(b []byte) ([]byte, bool)`: Strips whitespace and outer `[` and `]` brackets.
- `ParseNumeric(b []byte) (float64, bool)`: Parses integer, decimal, and scientific notation floats in zero allocations.
- `ParsePositiveInt(b []byte) (uint64, bool)`: Ultra-fast integer parser.
- `UnescapeJSONInPlace(s []byte) []byte`: Decodes escape sequences and Unicode code points in-place.
- `AppendEscapedJSONString(dst, s []byte) []byte`: Appends a JSON-safe quoted string.

---

## ⚠️ Sentinel Errors

All errors are pre-allocated static sentinels. Compare using `errors.Is` or `==` with zero heap allocations:

| Sentinel Error | Description |
| :--- | :--- |
| `ErrMissingBearer` | The `Authorization` header is missing the `"Bearer "` prefix. |
| `ErrInvalidToken` | Malformed token structure (does not have exactly 3 dot-separated Base64URL segments). |
| `ErrInvalidHeader` | Header is not valid JSON, or specifies an unsupported/mismatched algorithm. |
| `ErrInvalidSignature` | Cryptographic signature verification failed. |
| `ErrExpiredToken` | Current time is $\ge$ `exp` claim (taking `Leeway` into account). |
| `ErrNotValidYet` | Current time is $<$ `nbf` claim (taking `Leeway` into account). |
| `ErrInvalidPayload` | Payload JSON is malformed, missing required claims (`sub`), or types mismatch. |
| `ErrPayloadTooLarge` | Payload length exceeds `MaxPayloadSize`. |
| `ErrInvalidIssuer` | The `iss` claim does not match `ExpectedIssuer`. |
| `ErrInvalidAudience` | The `aud` claim does not match or contain `ExpectedAudience`. |
| `ErrUnknownKeyID` | The `"kid"` header specifies an unrecognized key ID. |

---

## 🧪 Testing, Fuzzing & Quality Assurance

`zerojwt` features a 100% comprehensive test and validation suite:

```bash
# 1. Run all unit tests with 100% statement coverage
go test -v -coverprofile=coverage.out ./...
go tool cover -func=coverage.out

# 2. Race detector (detects concurrency hazards)
go test -v -race ./...

# 3. Verify zero heap allocations on hot paths
go test -v -run=TestZeroAllocations ./...

# 4. Run benchmarks and memory allocation stats
go test -bench=. -benchmem ./...

# 5. Continuous native fuzz testing for adversarial inputs
go test -fuzz=FuzzVerify -fuzztime=30s
```

---

## 📄 License

MIT License — Copyright (c) 2026 [KaikeGM](https://github.com/KaikeGM).
Distributed under the permissive MIT license. See [LICENSE](LICENSE) for full details.
