# ⚡ zerojwt v2 (`github.com/KaikeGM/zerojwt/v2`)

**English** | [Português](README_pt-BR.md)

High-performance, zero-allocation JWT signing, verification, and JSON property streaming in Go 1.23+.

[![Go Reference](https://pkg.go.dev/badge/github.com/KaikeGM/zerojwt/v2.svg)](https://pkg.go.dev/github.com/KaikeGM/zerojwt/v2)
[![Coverage: 100%](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)](#)
[![Allocations: 0](https://img.shields.io/badge/allocations-0_allocs%2Fop-blue.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../LICENSE)

---

## 📑 Table of Contents

- [What is New in v2](#what-is-new-in-v2)
- [Benchmarks](#benchmarks)
- [Architecture & Memory Model](#architecture--memory-model)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Cryptographic Algorithms](#cryptographic-algorithms)
  - [Symmetric: HS256, HS384, HS512](#1-symmetric-hmac-hs256-hs384-hs512)
  - [Asymmetric: EdDSA (Ed25519)](#2-asymmetric-eddsa-ed25519--rfc-8037)
  - [Asymmetric: ES256 (ECDSA P-256)](#3-asymmetric-es256-ecdsa-p-256--rfc-7518)
- [RFC 7519 Validation & Claims](#rfc-7519-validation--claims)
  - [Single Unified Claims Struct](#single-unified-claims-struct)
  - [Clock Skew Tolerance (Leeway)](#clock-skew-tolerance-leeway)
  - [Issuer (iss) & Audience (aud) Validation](#issuer-iss--audience-aud-validation)
  - [JWT ID (jti) & Replay Prevention](#jwt-id-jti--replay-prevention)
- [Custom Claims & Fluent SignBuilder](#custom-claims--fluent-signbuilder)
  - [Fluent SignBuilder (0 allocs/op)](#fluent-signbuilder-0-allocsop)
  - [Generic JSON String Escaping (0 allocs/op)](#generic-json-string-escaping-0-allocsop)
  - [Atomic Claim Iteration (Go 1.23 iter.Seq2)](#atomic-claim-iteration-go-123-iterseq2)
- [Event-Driven Network Primitives (gnet, evio, epoll)](#event-driven-network-primitives-gnet-evio-epoll)
  - [Fragmented Ring-Buffer Validation (VerifySplit)](#1-fragmented-ring-buffer-validation-verifysplit)
  - [Worker-Pinned Cache-Padded Workspaces (WorkerScratchGroup)](#2-worker-pinned-cache-padded-workspaces-workerscratchgroup)
  - [Vectorized Scatter/Gather Signing (SignToIOV)](#3-vectorized-scattergather-signing-signtoiov)
  - [Complete Runnable Gateway Sample](#complete-runnable-gateway-sample)
- [Zero-Downtime Key Rotation (kid)](#zero-downtime-key-rotation-kid)
- [High-Speed HTTP Middlewares](#high-speed-http-middlewares)
  - [ProtectFunc (0 allocs/op)](#1-protectfunc-fastest-zero-allocation)
  - [Standard net/http Middleware](#2-standard-nethttp-middleware)
  - [VerifyBearer](#3-verifybearer)
- [Security Hardening & Memory Hygiene](#security-hardening--memory-hygiene)
- [Profile-Guided Optimization (PGO)](#profile-guided-optimization-pgo)
- [Sentinel Errors Reference](#sentinel-errors-reference)
- [Migration Guide from v1 to v2](#migration-guide-from-v1-to-v2)
- [License](#license)

---

## What is New in v2

`zerojwt/v2` represents the hardened, unified evolution of `zerojwt`, eliminating the historical dual-verifier dichotomy of v1 while guaranteeing **0 heap allocations (0 B/op, 0 allocs/op)** on all HS256 and Ed25519 signing and verification paths.

### Key Architectural Pillars

1. **Single Unified `Claims` Struct (1016 Bytes, Zero Heap Allocs)**
   - Replaces the separate `Claims` and `ClaimsLarge` types from v1 with a single unified struct.
   - Conforms strictly to **OIDC Core 1.0 §2**: Subject (`sub`) buffer expanded to 256 bytes (supporting up to 255 ASCII characters).
   - Structured with 8-byte CPU word alignment (56 bytes of flags/lengths, 6 bytes explicit padding, inline buffers for `sub` [256B], `iss` [256B], `aud` [256B], `user` [128B], and `jti` [64B]).
   - Verified via `unsafe.Sizeof(Claims{}) == 1016` and `unsafe.Alignof(Claims{}) == 8`.

2. **Secure by Default Constructor**
   - `New(secret, ...Options)` is strictly secure out of the box:
     - **RFC 7518 §3.2**: Rejects secrets shorter than the algorithm hash length (32 bytes for HS256, 48 for HS384, 64 for HS512) with `ErrInsecureSecret`.
     - **OIDC Core 1.0 §3.1.3.7 / RFC 9068 §2.2**: Rejects tokens missing the `exp` claim with `ErrMissingExp`.
   - Explicit opt-out flags are provided for legacy migration: `Options{AllowShortSecret: true, AllowMissingExp: true}`.

3. **Keypair Cross-Validation at Boot**
   - `NewEd25519Verifier`: Validates that `priv.Public()` matches `pub` with `ErrMismatchedKeyPair`.
   - `NewES256Verifier`: Validates that `priv.PublicKey` matches `pub`, and verifies scalar bounds $1 \le D < N$ per RFC 7518 §3.4.

4. **Idiomatic Append Contract with Zero-Alloc Rollback**
   - Signing methods (`Sign`, `SignClaims`, `SignBuilder`) return `([]byte, error)`.
   - Follows the standard Go `append` idiom: appends token bytes to the caller-supplied `dst`.
   - On error, `dst` is rolled back to its original length, preserving pre-allocated capacity without partial output corruption.

5. **Generic `AppendEscapedJSON[S ~string | ~[]byte]`**
   - Escapes user strings or byte slices into JSON strings without intermediate string conversions.
   - Dynamic 36-byte UUID strings are formatted into tokens with **0 heap allocations**.

6. **Atomic Verification Iterator (`Iter`)**
   - Leverages Go 1.23 standard iterators (`iter.Seq2[JSONProp, error]`).
   - Atomic verification guarantee: claims are yielded **if and only if** the token is 100% cryptographically verified and structurally valid. Any signature or header defect aborts iteration before yielding any claims.

7. **Event-Driven Network Primitives (`gnet`, `evio`, `epoll`)**
   - **`VerifySplit(head, tail, now, &claims)`**: Validates tokens fragmented across non-contiguous circular ring buffers with 0 heap allocations via 4-byte quantum seam stitching (~11.3 ns overhead).
   - **`WorkerScratchGroup`**: Fixed-size, cache-line padded (`PaddedScratch`) workspace array eliminating `sync.Pool` CAS contention and L1/L2 cache invalidations (*false sharing*) (~158.4 ns/op parallel verify).
   - **`SignToIOV(dst, pl, &iov)`**: Vectorized scatter/gather signing for `unix.Writev` / `gnet.Conn.Writev`. Skips copying the 37-byte header and streams HMAC directly into a stack `[2][]byte`.

8. **100.0% Statement Coverage & 0 Race Conditions**
   - All branches, sentinel errors, rotated key paths, split tokens, and IOV vectors verified with 100.0% test coverage.
   - Clean under `go test -race` and `go vet`.

---

## Benchmarks

Measured on Linux amd64 (11th Gen Intel Core i5-1135G7 @ 2.40GHz, Go 1.24):

### Standard API

| Benchmark | Description | Latency | Memory / op | Allocs / op |
| :--- | :--- | :---: | :---: | :---: |
| `BenchmarkVerifyHS256` | Single-core HS256 verification | **706.6 ns/op** | **0 B/op** | **0 allocs/op** |
| `BenchmarkVerifyLargeSubject` | Subject 250 bytes (OIDC limit) | **1170.0 ns/op** | **0 B/op** | **0 allocs/op** |
| `BenchmarkSignHS256` | Raw payload signing | **348.2 ns/op** | **0 B/op** | **0 allocs/op** |
| `BenchmarkSignClaims` | Standard registered claims signing | **417.2 ns/op** | **0 B/op** | **0 allocs/op** |
| `BenchmarkSignBuilder` | Dynamic fluent claim builder | **464.0 ns/op** | **0 B/op** | **0 allocs/op** |

### Event-Driven & Network Primitives (`gnet`, `evio`, `epoll`)

| Benchmark | Description | Latency | Memory / op | Allocs / op |
| :--- | :--- | :---: | :---: | :---: |
| `BenchmarkVerifyHS256_Contiguous` | Baseline single-buffer verification | **556.9 ns/op** | **0 B/op** | **0 allocs/op** |
| `BenchmarkVerifyHS256_VerifySplit` | Token fragmented across circular ring buffer (`head` + `tail`) | **564.8 ns/op** | **0 B/op** | **0 allocs/op** |
| `BenchmarkVerifyParallel_SyncPool` | High concurrency with `sync.Pool` | **162.2 ns/op** | **0 B/op** | **0 allocs/op** |
| `BenchmarkVerifyParallel_WorkerScratchGroup` | High concurrency worker-pinned (64B cache line padded, 0 lock contention) | **158.4 ns/op** | **0 B/op** | **0 allocs/op** |
| `BenchmarkSignHS256_Standard` | Standard single-buffer sign | **349.5 ns/op** | **0 B/op** | **0 allocs/op** |
| `BenchmarkSignHS256_SignToIOV` | Vectorized scatter/gather sign for `unix.Writev` / `Conn.Writev` | **355.8 ns/op** | **0 B/op** | **0 allocs/op** |

---

## Architecture & Memory Model

```
+----------------------------------------------------------------------------------------------------+
|                                    zerojwt v2 Memory Architecture                                  |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|  [ Stack / Local Frame ]                                                                           |
|  +----------------------------------------------------------------------------------------------+  |
|  | Claims Struct (1016 Bytes, 8-Byte Word Aligned)                                              |  |
|  | - Int64 claims: iat, nbf, exp (24 bytes)                                                     |  |
|  | - Lengths & Flags: subLen, issLen, audLen, userLen, jtiLen, presentFlags (32 bytes)          |  |
|  | - Padding: explicit 6 bytes (word alignment)                                                 |  |
|  | - Inline Buffers: sub [256B], iss [256B], aud [256B], user [128B], jti [64B]                |  |
|  +----------------------------------------------------------------------------------------------+  |
|                                                  ^                                                 |
|                                                  | (Decodes directly into stack fields)            |
|                                                  |                                                 |
|  [ Scratch Workspace (1472 Bytes, Worker or Pool Managed) ]                                        |
|  +----------------------------------------------------------------------------------------------+  |
|  | - Pre-initialized HMAC hashers (mac, keyMacs)                                                |  |
|  | - Signature Buffer: sigBuf [96B]                                                             |  |
|  | - Checksum Buffer: sumBuf [64B]                                                              |  |
|  | - DER Decode Buffer: derBuf [72B]                                                            |  |
|  | - Header Scratch Buffer: hdrBuf [128B]                                                       |  |
|  | - Payload Scratch Buffer: payloadBuf [1024B]                                                 |  |
|  +----------------------------------------------------------------------------------------------+  |
|                                                                                                    |
|  -> Zero dynamic heap allocations                                                                  |
|  -> Zero reflection (reflect)                                                                      |
|  -> Zero Garbage Collection sweeps in hot paths                                                    |
|                                                                                                    |
+----------------------------------------------------------------------------------------------------+
```

---

## Installation

```bash
go get github.com/KaikeGM/zerojwt/v2
```

Requires **Go 1.23.0** or newer.

---

## Quick Start

### Basic Signing and Verification (HS256)

```go
package main

import (
	"fmt"
	"time"

	"github.com/KaikeGM/zerojwt/v2"
)

func main() {
	secret := []byte("your-32-byte-ultra-secure-secret-key!")
	
	// Secure-by-default constructor (enforces >= 32B secret and required exp)
	v, err := zerojwt.New(secret)
	if err != nil {
		panic(err)
	}

	now := time.Now().Unix()

	// 1. Sign standard claims (0 heap allocations)
	token, err := v.SignClaims(nil, zerojwt.StandardClaims{
		Subject:   "usr_9847239847",
		Username:  "alex_dev",
		IssuedAt:  now,
		ExpiresAt: now + 3600, // Mandatory by default
	})
	if err != nil {
		panic(err)
	}

	// 2. Verify into pre-allocated Claims struct on stack (0 heap allocations)
	var claims zerojwt.Claims
	if err := v.Verify(token, now, &claims); err != nil {
		panic(err)
	}

	fmt.Printf("Authenticated: %s (%s)\n", claims.Subject(), claims.Username())
}
```

---

## Cryptographic Algorithms

### 1. Symmetric HMAC: HS256, HS384, HS512

`zerojwt/v2` validates HMAC keys at boot against RFC 7518 §3.2 minimum hash lengths:

```go
// HS256: secret >= 32 bytes
v256, err := zerojwt.New(secret32)

// HS384: secret >= 48 bytes
v384, err := zerojwt.New(secret48, zerojwt.Options{
    Algorithm: zerojwt.AlgHS384,
})

// HS512: secret >= 64 bytes
v512, err := zerojwt.New(secret64, zerojwt.Options{
    Algorithm: zerojwt.AlgHS512,
})
```

### 2. Asymmetric: EdDSA (Ed25519 / RFC 8037)

Provides ultra-fast asymmetric verification (~1.8 µs/op) with zero allocations and mathematical keypair cross-validation at boot:

```go
pub, priv, err := ed25519.GenerateKey(rand.Reader)
if err != nil {
    panic(err)
}

// Full signer + verifier (verifies priv.Public() == pub)
v, err := zerojwt.NewEd25519Verifier(pub, priv)

// Verifier only (public key only)
vVerifOnly, err := zerojwt.NewEd25519Verifier(pub, nil)
```

### 3. Asymmetric: ES256 (ECDSA P-256 / RFC 7518)

Validates NIST P-256 keys, cross-validates keypairs, and checks scalar bounds $1 \le D < N$:

```go
priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

// Full signer + verifier
v, err := zerojwt.NewES256Verifier(&priv.PublicKey, priv)
```

---

## RFC 7519 Validation & Claims

### Single Unified Claims Struct

In `zerojwt/v2`, `Claims` and `ClaimsLarge` are merged into a single 1016-byte struct:

```go
var claims zerojwt.Claims
if err := v.Verify(token, now, &claims); err != nil {
    // handle error
}

// Standard Claim Accessors (Zero Allocations: return []byte backed by inline buffers)
fmt.Printf("sub: %s\n", claims.Subject())        // []byte up to 256 bytes (OIDC Core §2)
fmt.Printf("user: %s\n", claims.Username())      // []byte up to 128 bytes
fmt.Printf("iss: %s\n", claims.Issuer())         // []byte up to 256 bytes
fmt.Printf("aud: %s\n", claims.Audience())       // []byte up to 256 bytes
fmt.Printf("jti: %s\n", claims.JTI())            // []byte up to 64 bytes
fmt.Println("exp:", claims.ExpiresAt)            // int64 Unix timestamp
fmt.Println("iat:", claims.IssuedAt)             // int64 Unix timestamp
fmt.Println("nbf:", claims.NotBefore)            // int64 Unix timestamp
fmt.Println("subID:", claims.SubjectID)          // int64 (parsed if sub is numeric)

// Presence Checking Flags (Direct Boolean Fields)
if claims.HasExp { /* exp was present in token */ }
if claims.HasIss { /* iss was present in token */ }
if claims.HasAud { /* aud was present in token */ }
if claims.HasSub { /* sub was present in token */ }
if claims.HasJti { /* jti was present in token */ }
```

### Clock Skew Tolerance (Leeway)

```go
v, err := zerojwt.New(secret, zerojwt.Options{
    Leeway: 60 * time.Second, // Allow 1 minute of server clock drift
})
```

### Issuer (iss) & Audience (aud) Validation

```go
v, err := zerojwt.New(secret, zerojwt.Options{
    ExpectedIssuer:   "https://auth.company.com",
    ExpectedAudience: "https://api.company.com",
})
```

### JWT ID (jti) & Replay Prevention

```go
// Read jti with zero heap allocations to check against a fast bitset / bloom filter / cache
if claims.HasJti {
    jti := claims.JTI()
    if isReplayed(jti) {
        return ErrInvalidToken
    }
}
```

---

## Custom Claims & Fluent SignBuilder

### Fluent SignBuilder (0 allocs/op)

```go
sb := v.NewSigner(nil)
token, err := sb.SetSubject("usr_12345").
    SetClaimString("role", "admin").
    SetClaimInt("tenant_id", 42).
    SetClaimBool("is_active", true).
    SetExpiresAt(now + 3600).
    Sign()
if err != nil {
    panic(err)
}
```

### Generic JSON String Escaping (0 allocs/op)

`AppendEscapedJSON` formats strings or byte slices into valid JSON without intermediate string allocations:

```go
buf := make([]byte, 0, 128)
buf = append(buf, `{"uuid":`...)
buf = zerojwt.AppendEscapedJSON(buf, "550e8400-e29b-41d4-a716-446655440000")
buf = append(buf, '}')
```

### Atomic Claim Iteration (Go 1.23 `iter.Seq2`)

Iterate over all custom and standard JSON properties in the verified payload with zero allocations:

```go
for prop, err := range v.Iter(token, now) {
    if err != nil {
        panic(err) // Aborts if signature or temporal validation fails
    }
    fmt.Printf("Claim %s = %s (isString: %v)\n", prop.Key, prop.Value, prop.IsString)
}
```

---

## Event-Driven Network Primitives (`gnet`, `evio`, `epoll`)

Designed specifically for event-driven network engines where packets are fragmented across ring buffers and worker threads must not contend on locks.

### 1. Fragmented Ring-Buffer Validation (`VerifySplit`)

When a TCP packet wraps around a circular ring buffer (e.g. `gnet`'s `ring.Buffer.Peek(n)`), the token is split into `head` and `tail`:

```go
// Direct streaming HMAC + 4-byte stack quantum Base64 boundary seam stitching
// Delta: only ~7.9 ns compared to a contiguous buffer, with 0 B/op and 0 allocs/op!
var claims zerojwt.Claims
if err := v.VerifySplitWithScratch(head, tail, now, &claims, scratch); err != nil {
    // handle error
}
```

### 2. Worker-Pinned Cache-Padded Workspaces (`WorkerScratchGroup`)

Eliminates `sync.Pool` atomic CAS contention (`LOCK CMPXCHG`) and CPU cache false sharing across cores:

```go
// Pre-allocate 1 Scratch per eventloop, padded to 64-byte L1/L2 cache line boundaries
workers := zerojwt.NewWorkerScratchGroup(v, runtime.NumCPU())

// In the event-loop callback (O(1), zero locks):
scratch := workers.For(workerID)
if err := v.VerifyWithScratch(token, now, &claims, scratch); err != nil {
    // handle error
}
```

### 3. Vectorized Scatter/Gather Signing (`SignToIOV`)

Outputs a 2-element scatter/gather I/O vector ready for `unix.Writev` / `gnet.Conn.Writev`:

```go
var dst [512]byte
var iov [2][]byte

// iov[0] -> Points to static pre-encoded header ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.")
// iov[1] -> Points to payload.signature generated directly in dst
err := v.SignClaimsToIOVWithScratch(dst[:0], zerojwt.StandardClaims{
    Subject:   "usr_123",
    ExpiresAt: now + 3600,
}, &iov, scratch)

// Write directly to kernel socket without copying the 37-byte header
conn.Writev(iov[:])
```

### Complete Runnable Gateway Sample

A complete production-ready TCP authentication gateway implementing all three primitives with `gnet` is available under [`examples/gnet`](../examples/gnet).

---

## Zero-Downtime Key Rotation (`kid`)

Verify tokens signed by older keys while issuing new tokens using the active key:

```go
v, err := zerojwt.New(primarySecret, zerojwt.Options{
    ActiveKeyID: "key-2026-v2", // Embedded into newly signed tokens
    Keys: []zerojwt.Key{
        {ID: "key-2026-v2", Secret: primarySecret},
        {ID: "key-2026-v1", Secret: retiredSecret}, // Still accepted for verification
    },
})
```

---

## High-Speed HTTP Middlewares

### 1. `ProtectFunc` (Fastest, Zero Allocation)

Passes a stack-allocated `*Claims` directly to the handler with **0 B/op and 0 allocs/op**:

```go
http.HandleFunc("/api/profile", v.ProtectFunc(func(w http.ResponseWriter, r *http.Request, claims *zerojwt.Claims) {
    w.Write([]byte("Hello, " + claims.Subject()))
}))
```

### 2. Standard `net/http` Middleware

Attaches `*Claims` to `r.Context()`:

```go
mux := http.NewServeMux()
mux.Handle("/api/dashboard", v.Middleware(http.HandlerFunc(DashboardHandler)))

func DashboardHandler(w http.ResponseWriter, r *http.Request) {
    claims := zerojwt.FromContext(r.Context())
    fmt.Fprintf(w, "User ID: %s", claims.Subject())
}
```

### 3. `VerifyBearer`

Directly validates an HTTP `Authorization` header with zero copies:

```go
authHeader := r.Header.Get("Authorization") // or fasthttp ctx.Request.Header.Peek("Authorization")
var claims zerojwt.Claims
if err := v.VerifyBearer([]byte(authHeader), now, &claims); err != nil {
    http.Error(w, "Unauthorized", http.StatusUnauthorized)
    return
}
```

---

## Security Hardening & Memory Hygiene

1. **`Destroy()` Memory Zeroing**:  
   Calling `v.Destroy()` marks the verifier as destroyed and zeroes out private keys and HMAC secrets with `0x00`. Subsequent calls fail closed with `ErrVerifierDestroyed`.
2. **Strict RFC 8259 Top-Level Header Parsing**:  
   Pre-authentication checks reject malformed headers, duplicate commas (`,,`), and invalid syntax before running cryptographic operations.
3. **Mandatory Expiration Enforcement**:  
   By default, tokens missing `exp` are rejected (`ErrMissingExp`), complying with OIDC Core 1.0 §3.1.3.7 and RFC 9068 §2.2.
4. **Secret Length Enforcement**:  
   Secrets shorter than the hash length are rejected at initialization with `ErrInsecureSecret` per RFC 7518 §3.2.

---

## Profile-Guided Optimization (PGO)

`zerojwt/v2` includes a pre-computed profile [`v2/default.pgo`](default.pgo) generated from real-world verification and signing workloads.

When building your application with Go 1.23+:
```bash
go build -pgo=auto .
```
The Go compiler automatically incorporates `default.pgo`, enabling aggressive function inlining and register allocation across all critical paths.

---

## Sentinel Errors Reference

| Error | Description |
| :--- | :--- |
| `ErrInvalidToken` | Token string is malformed or contains invalid Base64URL characters |
| `ErrInvalidHeader` | Header is missing, contains invalid JSON syntax, or specifies an unsupported algorithm |
| `ErrInvalidPayload` | Payload JSON is malformed or claims exceed maximum buffer sizes |
| `ErrInvalidSignature` | Cryptographic signature mismatch or token was corrupted/tampered |
| `ErrTokenExpired` | Current timestamp is greater than token `exp` (accounting for `Leeway`) |
| `ErrTokenNotValidYet` | Current timestamp is before token `nbf` (accounting for `Leeway`) |
| `ErrMissingExp` | Token lacks the required `exp` claim |
| `ErrPayloadTooLarge` | Decoded payload exceeds configured `MaxPayloadSize` |
| `ErrHeaderTooLarge` | Decoded header exceeds configured `MaxHeaderSize` |
| `ErrUnknownKeyID` | Token contains a `kid` header not registered in the key store |
| `ErrInvalidConfig` | Verifier configuration is invalid (e.g. short secret, invalid key) |
| `ErrVerifierDestroyed` | Verifier was invalidated via `Destroy()` |
| `ErrInvalidIssuer` | `iss` claim does not match `ExpectedIssuer` |
| `ErrInvalidAudience` | `aud` claim does not match `ExpectedAudience` |
| `ErrNoSigningKey` | Verifier holds no private key material for signing |
| `ErrSigningFailed` | Cryptographic signing failed during token emission |
| `ErrMismatchedKeyPair` | Public and private keys do not form a matching cryptographic pair |
| `ErrMissingBearer` | Authorization header does not begin with `Bearer ` |

---

## Migration Guide from v1 to v2

1. **Update Import Path**:
   Change `github.com/KaikeGM/zerojwt` to `github.com/KaikeGM/zerojwt/v2`.
2. **Update Constructor**:
   Replace `NewVerifier` or `NewSecureVerifier` with `zerojwt.New(secret, ...Options)`.
3. **Consolidate Claims**:
   Replace `ClaimsLarge` with `Claims`. All subjects up to 256 bytes are supported natively.
4. **Update Signing Signatures**:
   Replace `Sign(dst, pl)` returning `[]byte` with `Sign(dst, pl) ([]byte, error)`. Rollback on failure is automatic.
5. **Ensure Expiration**:
   Ensure issued tokens include `ExpiresAt > 0`. If legacy tokens without expiration must be accepted, pass `Options{AllowMissingExp: true}`.

---

## License

MIT License. See [LICENSE](../LICENSE) for details.
