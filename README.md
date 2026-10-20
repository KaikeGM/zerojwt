# ⚡ `zerojwt` — Ultra-Fast, Zero-Allocation Industrial JWT for Go

**English** | [Português](README_pt-BR.md)

[![Go Reference](https://pkg.go.dev/badge/github.com/KaikeGM/zerojwt.svg)](https://pkg.go.dev/github.com/KaikeGM/zerojwt)
[![Go Report Card](https://goreportcard.com/badge/github.com/KaikeGM/zerojwt)](https://goreportcard.com/report/github.com/KaikeGM/zerojwt)
[![Coverage](https://img.shields.io/badge/coverage-100.0%25-brightgreen.svg)](https://github.com/KaikeGM/zerojwt)
[![Allocations](https://img.shields.io/badge/allocations-0_B%2Fop-blue.svg)](https://github.com/KaikeGM/zerojwt)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`zerojwt` is a pure Go, zero-dependency library for signing and verifying **JSON Web Tokens (JWT / RFC 7519)** in **~215 ns/op (parallel) / ~415–700 ns/op (single-core)** with guaranteed **`0 B/op` and `0 allocs/op`** on critical execution paths.

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
- [Security Hardening & Memory Hygiene](#-security-hardening--memory-hygiene)
- [Profile-Guided Optimization (PGO)](#-profile-guided-optimization-pgo)
- [API Reference](#-api-reference)
- [Sentinel Errors](#-sentinel-errors)
- [Testing, Fuzzing & Quality Assurance](#-testing-fuzzing--quality-assurance)
- [License](#-license)

---

## 🚀 Benchmark Comparison

All benchmarks are 100% reproducible and published directly in this repository under the [`benchmarks/`](benchmarks/) directory. The benchmark suite tests each library with the **exact same cryptographic key, token payload, claims schema, and verification workload**.

> **Note on Zero Dependencies:** The competitor benchmarks are housed in a separate Go module (`benchmarks/go.mod`). This guarantees that your production code importing `github.com/KaikeGM/zerojwt` remains strictly **zero third-party dependencies**.

### 🔬 Reproducing the Benchmarks

Clone the repository and run the benchmark suite directly:

```bash
cd benchmarks
go test -bench=. -benchmem -benchtime=1s
```

All four libraries are verified for identical claim extraction and cryptographic correctness before the benchmark runs via `TestCompetitorsCompatibility`.

### 📊 Benchmark Results

*Environment: Intel(R) Core(TM) i5-1135G7 @ 2.40GHz (8 logical CPUs), Linux amd64, Go 1.23+.*
*Payload: HS256 32-byte secret, standard registered claims (`sub: "12345"`, `iat`, `exp`), plus custom claim (`user: "golden_ember_1"`).*
*Fair clock evaluation: Verification benchmarks for `zerojwt` invoke `time.Now().Unix()` on each iteration to match competing libraries that call system time internally.*

#### 1. Token Verification (Verify & Parse Claims)

| Library | Mode / Strategy | Throughput ($10^9 / \text{ns}$) | Avg Time / op | Memory / op | Allocs / op |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **`zerojwt`** | **Parallel (Multi-Core)** | **~4,750,000 ops/s** | **210.5 ns/op** | **`0 B/op`** | **`0 allocs/op`** |
| **`zerojwt`** | **Single-Core (Scratch)** | **~1,387,000 ops/s** | **720.9 ns/op** | **`0 B/op`** | **`0 allocs/op`** |
| **`zerojwt`** | **Single-Core (Pool)** | **~1,372,000 ops/s** | **728.5 ns/op** | **`0 B/op`** | **`0 allocs/op`** |
| `kataras/jwt` | Parallel (Multi-Core) | ~951,000 ops/s | 1,051.0 ns/op | 1,075 B/op | 15 allocs/op |
| `kataras/jwt` | Single-Core | ~354,000 ops/s | 2,821.0 ns/op | 1,073 B/op | 15 allocs/op |
| `golang-jwt/jwt/v5` | Parallel (Multi-Core) | ~575,000 ops/s | 1,739.0 ns/op | 2,097 B/op | 37 allocs/op |
| `golang-jwt/jwt/v5` | Single-Core | ~209,000 ops/s | 4,780.0 ns/op | 2,091 B/op | 37 allocs/op |
| `lestrrat-go/jwx/v2` | Parallel (Multi-Core) | ~185,000 ops/s | 5,385.0 ns/op | 6,135 B/op | 108 allocs/op |
| `lestrrat-go/jwx/v2` | Single-Core | ~91,000 ops/s | 10,948.0 ns/op | 6,112 B/op | 108 allocs/op |

#### 2. Token Generation (Signing)

| Library | Implementation | Throughput ($10^9 / \text{ns}$) | Avg Time / op | Memory / op | Allocs / op |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **`zerojwt`** | **`SignClaims`** | **~2,300,000 ops/s** | **434.7 ns/op** | **`0 B/op`** | **`0 allocs/op`** |
| **`zerojwt`** | **`SignBuilder`** | **~2,083,000 ops/s** | **480.0 ns/op** | **`0 B/op`** | **`0 allocs/op`** |
| `kataras/jwt` | `jwt.Sign` | ~619,000 ops/s | 1,613.0 ns/op | 1,208 B/op | 14 allocs/op |
| `golang-jwt/jwt/v5` | `SignedString` | ~276,000 ops/s | 3,617.0 ns/op | 2,338 B/op | 36 allocs/op |
| `lestrrat-go/jwx/v2` | `jwt.Sign` | ~131,000 ops/s | 7,617.0 ns/op | 4,933 B/op | 118 allocs/op |

> **Key takeaway:** Traditional JWT libraries allocate between 14 and 108 objects on the heap per token validation, accumulating megabytes of garbage and triggering constant GC pauses under production load (10k+ req/s). `zerojwt` performs **zero heap allocations**, allowing web gateways and event loops to handle maximum connection density with flat, predictable latencies.

---

## ✨ Key Features

1. **Strict 0 Allocations Guarantee:**
   - Token signing and verification with HS256/HS384/HS512 and EdDSA operate without heap allocations (`0 B/op, 0 allocs/op`). ES256 still allocates inside `crypto/ecdsa` (measured: ~8 allocs/op verify, ~33 allocs/op sign).
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

7. **Fail-Fast Configuration & Best-Effort Memory Hygiene:**
   - Constructors reject unusable key material (empty HMAC secrets, keys without material for the selected algorithm, wrong key sizes or curves) instead of building a verifier that accepts forged tokens.
   - Optional `ZeroMemory` mode wipes claims and scratch buffers via `memclr` before returning them to the pool. This is memory hygiene, not a compliance claim.

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

Requires Go 1.23 or newer:

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

> [!IMPORTANT]
> **Production Best Practices:**
> 1. **Always enforce token expiration:** RFC 7519 does not mandate the `exp` claim, so `zerojwt`'s default `Options{}` permits unexpired tokens if `exp` is omitted. For production APIs, configure `RequireExp: true` in `Options{}` so any token lacking `exp` is rejected immediately (`ErrMissingExp`).
> 2. **Check `Sign*` return value:** `Sign`, `SignClaims`, and `SignWithScratch` report failure by returning `nil` (e.g. when payload size exceeds `MaxPayloadSize`, signing key is missing, or `RequireExp` is violated). Always check `if token == nil { ... }`, or use `verifier.NewSigner()` for explicit typed errors (`ErrPayloadTooLarge`, etc.).

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

ES256 is widely used in enterprise OAuth 2.0 / OpenID Connect, mobile clients, and WebAuthn. `zerojwt` implements direct IEEE P1363 ($r \parallel s$) to ASN.1 DER conversion on stack buffers. Note that `crypto/ecdsa` itself allocates, so ES256 is not zero-allocation end to end.

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
defer builder.Discard() // Safely returns Scratch to pool if an error returns before Sign()

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

> **Memory safety tip:** `Sign()` automatically returns the pooled `*Scratch` instance on completion. Adding `defer builder.Discard()` protects against memory leaks when an error or early `return` occurs before `Sign()` is invoked; calling `Discard()` after `Sign()` is a safe no-op.

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
		// Go 1.23+ range-over-func iterator (0 B/op, 0 allocs/op, ~54 ns/op):
		for elem, isStr := range zerojwt.ArrayElements(val) {
			fmt.Printf("Permission: %s (isStr=%v)\n", elem, isStr)
		}
	}
	return true // continue scanning claims
})
```

### Go 1.23+ Zero-Allocation Range-Over-Func Iterators

Go 1.23 standardizes iterators via `iter.Seq` and `iter.Seq2`. `zerojwt` provides native iterators that compile down with complete closure inlining, running at **~18,000,000–19,000,000 ops/s** (~52–55 ns/op) with **`0 B/op` and `0 allocs/op`**:

```go
// 1. Iterate over JSON array elements (non-destructive, safe for multiple passes):
for elem, isStr := range zerojwt.ArrayElements(rawArray) {
	fmt.Printf("Element: %s (isStr: %v)\n", elem, isStr)
}

// 2. Iterate over JSON object properties (key, val):
for key, val := range zerojwt.ObjectProps(rawObject) {
	fmt.Printf("%s = %s\n", key, val)
}

// 3. Iterate over properties with full type information:
for prop := range zerojwt.ObjectProperties(rawObject) {
	fmt.Printf("Key: %s, Val: %s, IsString: %v\n", prop.Key, prop.Val, prop.IsStr)
}
```

> **String values note:** String elements and property values are yielded as non-destructive slices into the underlying buffer with enclosing quotes stripped, retaining escape sequences (e.g., `\"`, `\n`) to preserve buffer immutability across multiple passes. Call `zerojwt.UnescapeJSONInPlace(val)` if decoded strings are needed.

#### Strict Error Detection

When iterating over untrusted or external JSON payloads, iterators accept an optional `*error` pointer. If the JSON structure is truncated or encounters invalid syntax, iteration stops gracefully and assigns `zerojwt.ErrInvalidPayload`:

```go
var scanErr error
for elem, isStr := range zerojwt.ArrayElements(rawArray, &scanErr) {
	// ...
}
if scanErr != nil {
	return fmt.Errorf("malformed claims array: %w", scanErr)
}
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
	},
})
```

Every key must carry material for the verifier's algorithm: `Secret` for HS256/384/512, a 32-byte `Ed25519Public` for EdDSA, a P-256 `ECDSAPublic` for ES256. IDs must be non-empty and unique. A key that does not match the algorithm is a configuration error (see [Security Hardening](#-security-hardening--memory-hygiene)); a verifier handles one algorithm, so keys of different algorithms cannot be mixed in one `Verifier`.

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

> `Middleware` stores the claims in the request `context`, which allocates. Use `ProtectFunc` when you need zero allocations per request.

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

## 🛡️ Security Hardening & Memory Hygiene

### Fail-Fast Configuration

`NewVerifier`, `NewVerifierWithOptions`, `NewEd25519Verifier` and `NewES256Verifier` **panic** with an error wrapping `zerojwt.ErrInvalidConfig` when the configuration is unusable, so a missing `JWT_SECRET` crashes at startup instead of silently accepting forged tokens. To handle the error yourself, use `TryNewVerifier`:

```go
v, err := zerojwt.TryNewVerifier([]byte(os.Getenv("JWT_SECRET")), zerojwt.Options{
	Algorithm:          zerojwt.AlgHS256,
	RequireExp:         true, // reject tokens without "exp"; SignClaims/SignBuilder refuse to omit it
	StrictSecretLength: true, // enforce the RFC 7518 §3.2 minimum: 32/48/64 bytes for HS256/384/512
})
if err != nil {
	log.Fatal(err) // errors.Is(err, zerojwt.ErrInvalidConfig)
}
```

Always rejected: empty HMAC secrets, `Key`s without material for the selected algorithm, empty or duplicate key IDs, unknown algorithm names, wrong Ed25519 key sizes and non-P-256 ECDSA keys. `StrictSecretLength` is opt-in so existing deployments with shorter (but non-empty) secrets keep working.

### Strict Token Form and Headers

A token has exactly one accepted string form: Base64URL is decoded in strict mode (non-canonical trailing bits are rejected) and any `\r` or `\n` in the token is rejected. This matters if you key a revocation list or replay cache on the token string. A `crit` header is rejected, as RFC 7515 §4.1.11 requires for unsupported critical extensions.

### Verify-Only Nodes

`Verifier.CanSign()` reports whether the verifier holds a signing key. On verify-only nodes (for example EdDSA/ES256 without a private key) the `Sign*` methods return `nil` and `SignBuilder.Sign` returns `ErrNoSigningKey`; they never return a token with an invalid signature.

### Memory Hygiene (`ZeroMemory`, `Destroy`)

Enable `ZeroMemory: true` to `memclr` claims and scratch buffers before they go back to the pool:

```go
verifier := zerojwt.NewVerifierWithOptions(secret, zerojwt.Options{
	ZeroMemory: true,
})
```

`verifier.Destroy()` wipes the secrets the verifier owns and makes it unusable (`Verify*` returns `ErrVerifierDestroyed`, `Sign*` returns `nil`). This is best-effort hygiene, **not** a FIPS / PCI-DSS compliance claim: copies of keys you passed in, HMAC state cached inside pooled Scratch values (the standard library's hmac keeps key-derived pads) and an `*ecdsa.PrivateKey` you share with the Verifier (only the reference is dropped).
Destroy must not be called concurrently with other methods.

---

## ⚡ Profile-Guided Optimization (PGO)

When compiling production binaries, Go 1.20+ supports Profile-Guided Optimization (PGO). The Go compiler automatically detects and uses a `default.pgo` profile file located directly in the **`main` package directory** being built.

Because Go applies PGO at the executable level rather than per-dependency, you can optimize your entire service (including `zerojwt`'s inner verification and parsing routines) by collecting a profile from production:

```bash
# 1. Capture a representative 30-second CPU profile from your running service
curl -o default.pgo "http://localhost:6060/debug/pprof/profile?seconds=30"

# 2. Place default.pgo in your main package directory (alongside main.go)

# 3. Compile with Go 1.23+ (the compiler automatically discovers default.pgo)
go build -o my-service .
```

To verify PGO optimizations during the build:

```bash
go build -gcflags="-m=2" 2>&1 | grep "pgo inline"
```

---

## 📖 API Reference

### Verifier Constructors
- `NewVerifier(secret []byte) *Verifier`: Creates an HS256 verifier with default buffer limits (128B header, 1024B payload).
- `NewEd25519Verifier(pub ed25519.PublicKey, priv ed25519.PrivateKey, opts Options) *Verifier`: Creates an EdDSA (Ed25519) verifier.
- `NewES256Verifier(pub *ecdsa.PublicKey, priv *ecdsa.PrivateKey, opts Options) *Verifier`: Creates an ES256 (ECDSA P-256) verifier.
- `NewVerifierWithOptions(secret []byte, opts Options) *Verifier`: Creates a fully configured verifier. Panics (wrapping `ErrInvalidConfig`) on unusable configuration.
- `TryNewVerifier(secret []byte, opts Options) (*Verifier, error)`: Same, but returns the error instead of panicking.
- `(*Verifier).CanSign() bool`: Reports whether the verifier holds a signing key.

### Verification Methods
- `Verify(tok []byte, nowUnix int64, out *Claims) error`: Validates token into standard `Claims`.
- `VerifyBearer(authHeader []byte, nowUnix int64, out *Claims) error`: Extracts `Bearer <token>` and validates.
- `VerifyWithScratch(tok []byte, nowUnix int64, out *Claims, st *Scratch) error`: Validates token using a caller-supplied `Scratch`.
- `VerifyLarge(tok []byte, nowUnix int64, out *ClaimsLarge) error`: Validates token into large-capacity `ClaimsLarge`.
- `VerifyLargeWithScratch(tok []byte, nowUnix int64, out *ClaimsLarge, st *Scratch) error`: Validates token into `ClaimsLarge` using caller-supplied `Scratch`.
- `VerifyCustom(tok []byte, nowUnix int64, onClaim func(key, val []byte, isStr bool) bool) error`: Validates signature and temporal claims, scanning arbitrary claims with zero allocations.

### Signing Methods & Builder
All `Sign*` methods return `nil` (never a token with a bogus signature) when the verifier cannot sign (`CanSign() == false`), when the signing operation fails, or, with `RequireExp`, when `SignClaims` is called with `exp <= 0`.

- `Sign(dst []byte, payloadJSON []byte) []byte`: Signs raw JSON payload using default buffers.
- `SignClaims(dst, sub, username []byte, iat, exp int64) []byte`: Signs standard claims directly into `dst`.
- `SignWithScratch(dst, payloadJSON []byte, st *Scratch) []byte`: Signs payload using caller-supplied `Scratch`.
- `NewSigner(dst []byte) SignBuilder`: Creates a fluent builder for custom claims backed by `sync.Pool`.
- `NewSignerWithScratch(dst []byte, st *Scratch) SignBuilder`: Creates a fluent builder using caller-supplied `Scratch`.
- `(*SignBuilder).Discard()`: Releases internal `Scratch` buffer back to `sync.Pool` if owned (idempotent).
- `(*SignBuilder).Sign() ([]byte, error)`: Signs the payload and automatically releases pooled `Scratch`.

### Fast Lexer & Parser (`scanner.go`)
- `NextJSONProp(b []byte) (key, val []byte, isStr bool, rest []byte, ok bool)`: Extracts the next `"key": value` from a JSON object body in-place.
- `NextArrayElement(b []byte) (val []byte, isStr bool, rest []byte, ok bool)`: Extracts the next element from a JSON array body in-place.
- `TrimJSONObject(b []byte) ([]byte, bool)`: Strips whitespace and outer `{` and `}` braces.
- `TrimJSONArray(b []byte) ([]byte, bool)`: Strips whitespace and outer `[` and `]` brackets.
- `ParseNumeric(b []byte) (float64, bool)`: Parses integer, decimal, and scientific notation floats in zero allocations.
- `ParsePositiveInt(b []byte) (int64, bool)`: Ultra-fast 64-bit integer parser supporting up to 19 digits (Snowflake IDs).
- `UnescapeJSONInPlace(s []byte) []byte`: Decodes escape sequences and Unicode code points in-place.
- `AppendEscapedJSONString(dst, s []byte) []byte`: Appends a JSON-safe quoted string.

### Go 1.23+ Iterators (`iter.go`)
- `ArrayElements(rawArray []byte, errOut ...*error) iter.Seq2[[]byte, bool]`: Non-destructive traversal of JSON array elements with zero allocations.
- `ObjectProps(rawObject []byte, errOut ...*error) iter.Seq2[[]byte, []byte]`: Non-destructive traversal of JSON object key-value pairs with zero allocations.
- `ObjectProperties(rawObject []byte, errOut ...*error) iter.Seq[JSONProp]`: Non-destructive traversal of JSON object properties with full type metadata.

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
| `ErrMissingExp` | `RequireExp` is set and the token has no `exp` claim. |
| `ErrInvalidConfig` | Wrapped by `TryNewVerifier` errors and constructor panics for unusable configuration. |
| `ErrNoSigningKey` | `SignBuilder.Sign` was called on a verifier that cannot sign. |
| `ErrVerifierDestroyed` | A `Verify*` method was called after `Destroy()`. |

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
