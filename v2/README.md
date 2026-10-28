# ⚡ zerojwt v2 (`github.com/KaikeGM/zerojwt/v2`)

**English** | [Português](README_pt-BR.md)

High-performance, zero-allocation JWT signing, verification, and JSON property streaming in Go 1.23+.

[![Go Reference](https://pkg.go.dev/badge/github.com/KaikeGM/zerojwt/v2.svg)](https://pkg.go.dev/github.com/KaikeGM/zerojwt/v2)
[![Coverage: 100%](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)](#)
[![Allocations: 0](https://img.shields.io/badge/allocations-0_allocs%2Fop-blue.svg)](#)
[![XERJ Corpus Hub contributor](https://hub.xerj.org/contributors/KaikeGM/badge.svg)](https://hub.xerj.org/contributors/KaikeGM)
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
  - [Asymmetric: ES256, ES384, ES512 (ECDSA)](#3-asymmetric-es256-es384-es512-ecdsa--rfc-7518)
  - [Asymmetric: RS256 (RSA PKCS#1 v1.5)](#4-asymmetric-rs256-rsa-pkcs1-v15--rfc-7518)
- [RFC 7519 Validation & Claims](#rfc-7519-validation--claims)
  - [Single Unified Claims Struct](#single-unified-claims-struct)
  - [Clock Skew Tolerance (Leeway)](#clock-skew-tolerance-leeway)
  - [Issuer (iss) & Audience (aud) Validation](#issuer-iss--audience-aud-validation)
  - [JWT ID (jti) & Replay Prevention](#jwt-id-jti--replay-prevention)
- [Custom Claims & Fluent SignBuilder](#custom-claims--fluent-signbuilder)
  - [Fluent SignBuilder (0 allocs/op)](#fluent-signbuilder-0-allocsop)
  - [Generic JSON String Escaping (0 allocs/op)](#generic-json-string-escaping-0-allocsop)
  - [Atomic Claim Iteration (Go 1.23 iter.Seq2 & IterSplit)](#atomic-claim-iteration-go-123-iterseq2--itersplit)
- [Event-Driven Network Primitives (gnet, evio, epoll)](#event-driven-network-primitives-gnet-evio-epoll)
  - [Fragmented Ring-Buffer Validation (VerifySplit)](#1-fragmented-ring-buffer-validation-verifysplit)
  - [Worker-Pinned Cache-Padded Workspaces (WorkerScratchGroup)](#2-worker-pinned-cache-padded-workspaces-workerscratchgroup)
  - [Vectorized Scatter/Gather Signing (SignToIOV)](#3-vectorized-scattergather-signing-signtoiov)
  - [Complete Runnable Gateway Sample](#complete-runnable-gateway-sample)
- [Key Rotation & Native RFC 7517 JWKS](#key-rotation--native-rfc-7517-jwks)
  - [Static Multi-Key Registration](#1-static-multi-key-registration-kid)
  - [Lock-Free Dynamic Key Rotation (UpdateKeys)](#2-lock-free-dynamic-key-rotation-updatekeys)
  - [Native RFC 7517 JWKS Parser (UpdateKeysFromJWKS)](#3-native-rfc-7517-jwks-parser-updatekeysfromjwks)
- [High-Speed HTTP Middlewares](#high-speed-http-middlewares)
  - [ProtectFunc (0 allocs/op)](#1-protectfunc-fastest-zero-allocation)
  - [Standard net/http Middleware](#2-standard-nethttp-middleware)
  - [VerifyBearer](#3-verifybearer)
  - [Turnkey ForwardAuth for Nginx & Traefik](#4-turnkey-forwardauth-for-nginx--traefik)
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
     - **RFC 7518 §3.2**: Rejects secrets shorter than the algorithm hash length (32 bytes for HS256, 48 for HS384, 64 for HS512) with `ErrInvalidConfig` (or alias `ErrInsecureSecret`).
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

### Reproducing Benchmarks Locally

Anyone can reproduce the benchmark suite directly against `golang-jwt/jwt/v5`, `lestrrat-go/jwx/v2`, and `kataras/jwt` in seconds:

```bash
cd benchmarks && go test -bench=. -benchmem
```

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
|  | - Inline Buffers: sub [256B], iss [256B], aud [256B], user [128B], jti [64B]                 |  |
|  +----------------------------------------------------------------------------------------------+  |
|                                                  ^                                                 |
|                                                  | (Decodes directly into stack fields)            |
|                                                  |                                                 |
|  [ Scratch Workspace (3512 Bytes, Worker or Pool Managed) ]                                        |
|  +----------------------------------------------------------------------------------------------+  |
|  | - Pre-initialized HMAC hashers & rotation state (mac, keyMacs, keyVersion [8B])              |  |
|  | - Signature Buffer: sigBuf [512B] (supports RSA-2048/3072/4096, ES512)                       |  |
|  | - Checksum Buffer: sumBuf [64B]                                                              |  |
|  | - DER Decode Buffer: derBuf [144B] (P-256, P-384, P-521 long-form DER)                       |  |
|  | - Header Scratch Buffer: hdrArr [128B] / hdrBuf                                              |  |
|  | - Payload Scratch Buffer: payloadArr [1024B] / payloadBuf                                    |  |
|  | - Signing Assembly Buffer: signArr [1544B] (Base64 Header + '.' + Payload)                   |  |
|  +----------------------------------------------------------------------------------------------+  |
|                                                                                                    |
|  -> Zero dynamic heap allocations                                                                  |
|  -> Zero reflection (reflect)                                                                      |
|  -> Zero Garbage Collection sweeps in hot paths                                                    |
|                                                                                                    |
+----------------------------------------------------------------------------------------------------+
```

### Explicit Memory Bounds & Guarantees

- **Split Verification Ceiling (`VerifySplit`):**
  - `st.signArr` has a fixed size of `[1544]byte`. For default `MaxHeaderSize: 128` (171 bytes Base64URL) and `MaxPayloadSize: 1024` (1366 bytes Base64URL), the maximum combined signing input is 1538 bytes, guaranteeing **`0 allocs/op`** during fragmented `VerifySplit`.
  - The zero-allocation guarantee assumes the default `MaxHeaderSize: 128`. Increasing either `MaxHeaderSize` or `MaxPayloadSize` may cause asymmetric algorithms (`EdDSA`, `ECDSA`, `RSA`) to dynamically allocate during `stitchSigningInput` if the combined signing input exceeds `MaxZeroAllocSplitSigningInput` (1544 bytes, or `MaxZeroAllocSplitPayloadSize: 1024`).
  - For symmetric HMAC algorithms (`HS256`, `HS384`, `HS512`), `VerifySplit` streams fragments directly into the hasher (`mac.Write(part1)` followed by `mac.Write(part2)`), **never allocating regardless of header or payload size**.
- **Lock-Free Key Rotation Warmup & ZeroMemory Finalizers:**
  - When calling `UpdateKeys` or `UpdateKeysFromJWKS`, new HMAC hashers are initialized lazily on the first verification for each worker/scratch workspace (`getOrInitKeyMacSlow`). All subsequent steady-state requests remain 100% `0 B/op, 0 allocs/op`.
  - When `ZeroMemory: true` is enabled, replaced `keySet` generations are zeroed out via `runtime.SetFinalizer`. This means memory wiping occurs on the subsequent GC cycle after the last concurrent in-flight verification finishes (rather than synchronously blocking inside `UpdateKeys`), completely eliminating data races while guaranteeing cryptographic erasure. Note that finalizers require two GC cycles to fully reclaim underlying memory and run on Go's dedicated runtime finalizer queue.
- **Zero-Allocation String Helpers (`VerifyString`, `VerifyBearerString`):**
  - Web frameworks and standard `net/http` handlers often parse tokens from string headers (`r.Header.Get`), cookies, or URL parameters.
  - Calling `VerifyStringNow(tok, &claims)` or `VerifyBearerStringNow(authHeader, &claims)` performs an immutable zero-allocation byte conversion under Go 1.20+, avoiding the 1 heap allocation of `[]byte(str)`.

---

## Installation

```bash
go get github.com/KaikeGM/zerojwt/v2
```

Requires **Go 1.23.0** or newer.

---

## Quick Start

### Basic Signing and Verification (HS256)

> [!TIP]
> **Zero Configuration & Automatic Workspace Pooling:**
> Standard methods (`v.Verify`, `v.VerifyNow`, `v.VerifyBearerNow`, `v.Sign`, `v.SignClaims`) automatically manage pre-allocated workspaces via an internal, lock-free `sync.Pool` with guaranteed **`0 B/op` and `0 allocs/op`**.
> You **do not** need to touch `Scratch` or manage buffers manually. Low-level primitives like `Scratch` and `WorkerScratchGroup` are strictly optional optimizations for event-driven network engines (`gnet`, `evio`, `epoll`).

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
	// You can use v.Verify(token, now, &claims) or the ergonomic v.VerifyNow(token, &claims):
	var claims zerojwt.Claims
	if err := v.VerifyNow(token, &claims); err != nil {
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

### 3. Asymmetric: ES256, ES384, ES512 (ECDSA / RFC 7518)

Validates NIST P-256, P-384, and P-521 keys with strict IEEE P1363 <-> ASN.1 DER conversion, keypair cross-validation, and scalar bounds $1 \le D < N$:

```go
// ES256 (NIST P-256 with SHA-256)
priv256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
v256, err := zerojwt.NewES256Verifier(&priv256.PublicKey, priv256)

// ES384 (NIST P-384 with SHA-384)
priv384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
v384, err := zerojwt.NewES384Verifier(&priv384.PublicKey, priv384)

// ES512 (NIST P-521 with SHA-512, handles 66-byte coordinates and long-form DER)
priv521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
v521, err := zerojwt.NewES512Verifier(&priv521.PublicKey, priv521)
```

### 4. Asymmetric: RS256 (RSA PKCS#1 v1.5 / RFC 7518)

High-speed asymmetric verification (~28 µs/op with short public exponent $e = 65537$) with native compatibility for Auth0, Keycloak, Microsoft Entra ID, Google, and AWS Cognito:

```go
privRSA, _ := rsa.GenerateKey(rand.Reader, 2048)

// Full signer + verifier (cross-validates priv.PublicKey == pub and priv.Validate())
vRSA, err := zerojwt.NewRS256Verifier(&privRSA.PublicKey, privRSA)

// Verifier only (public key only: enforces 2048-4096 bit modulus, odd N, e >= 65537)
vRSAOnly, err := zerojwt.NewRS256Verifier(&privRSA.PublicKey, nil)
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

### Atomic Claim Iteration (Go 1.23 `iter.Seq2` & `IterSplit`)

Iterate over all custom and standard JSON properties in the verified payload with zero allocations using `IterWithScratch` and `IterSplitWithScratch`:

```go
// Zero-allocation path (0 B/op, 0 allocs/op with worker/reusable scratch):
scratch := workers.For(workerID) // or v.NewScratch()

// Contiguous token:
for prop, err := range v.IterWithScratch(token, now, scratch) {
    if err != nil {
        panic(err) // Aborts if signature or temporal validation fails
    }
    fmt.Printf("Claim %s = %s (isString: %v)\n", prop.Key, prop.Val, prop.IsStr)
}

// Fragmented ring-buffer token (head + tail):
for prop, err := range v.IterSplitWithScratch(head, tail, now, scratch) {
    if err != nil {
        panic(err)
    }
    fmt.Printf("Split Claim %s = %s\n", prop.Key, prop.Val)
}
```

> [!NOTE]
> For convenience, `v.Iter(token, now)` and `v.IterSplit(head, tail, now)` are also provided without requiring an explicit scratch pointer; they dynamically acquire workspaces via `sync.Pool` (~3 allocs/op in Go 1.23; 0 in Go 1.24+). Use `IterWithScratch` / `IterSplitWithScratch` for guaranteed zero heap allocations across all Go versions (Go 1.23+).

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

## Key Rotation & Native RFC 7517 JWKS

### 1. Static Multi-Key Registration (`kid`)

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

### 2. Lock-Free Dynamic Key Rotation (`UpdateKeys`)

Atomically swap the registered `kid` key set in live production traffic with zero downtime and zero mutex locking via `atomic.Pointer`:

```go
// Dynamically replace the key set during live traffic:
err := v.UpdateKeys([]zerojwt.Key{
    {ID: "key-2026-v3", Secret: nextGenSecret},
    {ID: "key-2026-v2", Secret: primarySecret},
})
```

### 3. Native RFC 7517 JWKS Parser (`UpdateKeysFromJWKS`)

Parse and ingest standard JSON Web Key Sets (RFC 7517) from Identity Providers (e.g. Auth0, Keycloak, Okta, AWS Cognito) with **0 external dependencies**:

```go
// Pure Go JWKS parsing (supports oct, OKP/Ed25519, EC P-256/P-384/P-521, and RSA 2048-4096):
keys, err := zerojwt.ParseJWKS(jwksJSONBytes)

// Or rotate the Verifier's key store directly from raw JWKS JSON without downtime:
err = v.UpdateKeysFromJWKS(jwksJSONBytes)
```

#### Cryptographic & RFC Compliance Guarantees:
- **Strict EC Coordinate Lengths (RFC 7518 §6.2.1.2 & §6.2.1.3)**: Coordinates `x` and `y` must be strictly 32 octets for P-256, 48 octets for P-384, and 66 octets for P-521. Non-canonical leading-zero truncation or zero-padded inflation are rejected.
- **Strict RSA Key Validation (RFC 7518 §6.3)**: Leading zeros on `Base64urlUInt` encodings for `n` and `e` are prohibited (`nBytes[0] == 0 || eBytes[0] == 0`). Modulus $N$ must be odd and between 2048 and 4096 bits; public exponent $E$ must be odd with $65537 \le E \le 2^{31}-1$.
- **Wycheproof Curve Verification**: Validates public keys against curve equations (`elliptic.Curve.IsOnCurve`), rejecting identity points $(0,0)$ and off-curve coordinates at parse time.
- **RFC 7517 `use` & `key_ops` Matrix**:
  - `use`: strictly validated as a string; accepts `"sig"` and `"enc"`; rejects all other values.
  - `key_ops`: must be a non-empty JSON array of non-empty strings. Rejects conflicting assignments (e.g. `"use": "sig"` with encryption operations or `"use": "enc"` with signing operations). Chaves lacking `"verify"` are skipped without failing the JWKS document.
- **Data Type & Key ID Integrity**:
  - Rejects non-string types for `kty`, `kid`, `crv`, `k`, `x`, and `y`.
  - Rejects duplicate `kid` values within the document to prevent key shadowing.
  - Rejects algorithm mismatch (`"alg": "ES256"` on an `oct` key, or `"alg": "none"`).
  - Strict Base64URL decoding rejects embedded `\r` and `\n` characters.

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

### 4. Turnkey ForwardAuth for Nginx & Traefik

A turnkey HTTP handler specifically tailored for reverse proxy authentication subrequests. Responds with `200 OK` on valid tokens and automatically injects authentication headers (`X-Auth-User`, `X-Auth-Sub`) for upstream request enrichment; rejects invalid or expired tokens with `401 Unauthorized`:

```go
// Standard ForwardAuth endpoint (supports Bearer tokens, custom headers, and cookies)
http.HandleFunc("/auth", v.ForwardAuthHandler(zerojwt.ForwardAuthOptions{
    CookieName: "access_token", // Fallback to cookie if Authorization header is absent
}))
```

#### Nginx `ngx_http_auth_request_module` Integration:

```nginx
location /api/ {
    auth_request /auth;
    auth_request_set $auth_user $upstream_http_x_auth_user;
    auth_request_set $auth_sub  $upstream_http_x_auth_sub;
    
    proxy_set_header X-User $auth_user;
    proxy_set_header X-Sub  $auth_sub;
    proxy_pass http://upstream_backend;
}

location = /auth {
    internal;
    proxy_pass http://auth_service:8080/auth;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
}
```

#### Traefik `ForwardAuth` Middleware:

```yaml
http:
  middlewares:
    zerojwt-auth:
      forwardAuth:
        address: "http://auth_service:8080/auth"
        authResponseHeaders:
          - "X-Auth-User"
          - "X-Auth-Sub"
```

> [!IMPORTANT]
> **HTTP Header Injection & Response Splitting Prevention (CWE-113)**:  
> `ForwardAuthHandler` strictly inspects `Username()` and `Subject()` claims before setting identity headers. If any ASCII control characters (`< 0x20` or `0x7f`, such as `\r`, `\n`, or `\x00`) are present, the handler terminates immediately with `401 Unauthorized` and suppresses all header injection, preventing reverse proxy cache poisoning or header manipulation in Nginx and Traefik.

---

## Security Hardening & Memory Hygiene

1. **`Destroy()` Memory Zeroing**:  
   Calling `v.Destroy()` marks the verifier as destroyed and zeroes out private keys and HMAC secrets with `0x00`. Subsequent calls fail closed with `ErrVerifierDestroyed`.
2. **Strict RFC 8259 Top-Level Header & Lexer Parsing**:  
   Pre-authentication checks validate separators, numbers, bracket structure, and string literals (strictly rejecting unescaped control characters `< 0x20`, invalid escape sequences, and incomplete `\uXXXX` sequences per RFC 8259 §7) before running cryptographic operations, verified via differential fuzzing against `encoding/json`.
3. **Mandatory Expiration Enforcement**:  
   By default, tokens missing `exp` are rejected (`ErrMissingExp`), complying with OIDC Core 1.0 §3.1.3.7 and RFC 9068 §2.2.
4. **Secret Length Enforcement**:  
   Secrets shorter than the hash length are rejected at initialization with `ErrInvalidConfig` (`ErrInsecureSecret`) per RFC 7518 §3.2.
5. **Defensive Key Material Cloning**:  
   To prevent data races and concurrent external mutations, `ecdsa.PublicKey` coordinates (`X` and `Y` `big.Int`s) and raw secret/OKP slices are deep-copied into private internal structures during compilation (`compileKeys`), ensuring verifiers are thread-safe and completely immutable.
6. **Strict Coordinate & Curve Geometry Checks**:  
   Elliptic curve public keys are verified against curve equations at parse and registration time (`isValidP256PublicKey`), rejecting points not on curve P-256 and the point at infinity $(0,0)$.
7. **HTTP Header Injection & CRLF Immunity**:  
   Reverse proxy headers generated by `ForwardAuthHandler` fail closed on any control bytes in subject or username claims.

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
6. **Key ID Enforcement (`kid`)**:
   Tokens containing a `kid` header now require a matching key in `Keys` or registered via `UpdateKeys` / JWKS. If the `kid` is unknown, `Verify` returns `ErrUnknownKeyID` immediately.

---

## License

MIT License. See [LICENSE](../LICENSE) for details.
