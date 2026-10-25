# Changelog

All notable changes to `zerojwt` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v2.3.1] - 2026-10-24

### Added
- **Ergonomic Timestamp-Free Verification Helpers (`v2/jwt.go`, `v2/split.go`):**
  - Added `v.VerifyNow(token, &claims)`: verifies tokens against current system time (`time.Now().Unix()`) with automatic workspace pooling.
  - Added `v.VerifyBearerNow(authHeader, &claims)`: strips and validates `Authorization: Bearer <token>` in a single step using current system time.
  - Added `v.VerifySplitNow(head, tail, &claims)`: verifies tokens fragmented across circular ring buffers using current system time.
- **Documentation & Package-Level Visibility:**
  - Mirrored `CHANGELOG.md` into `v2/CHANGELOG.md` for direct visibility on `pkg.go.dev/github.com/KaikeGM/zerojwt/v2` and GitHub directory view.
  - Added explicit callouts in Quick Start guides clarifying that `v.Verify` / `v.Sign` automatically manage workspaces via an internal, lock-free `sync.Pool` with guaranteed `0 B/op` and `0 allocs/op`.
  - Added prominent `v2.3.1` announcement banners in root `README.md` and `README_pt-BR.md`.

### Fixed
- **Cross-Version Go Compatibility in RSA Tests (`v2/v230_test.go`):**
  - Fixed `TestV230_ConfigValidation` on Go 1.24 and Go 1.25 by setting `corruptPriv.Primes = nil` instead of modifying `D`, ensuring `priv.Validate()` returns `crypto/rsa: missing primes` across all Go versions (Go 1.23 to Go 1.27+).

---

## [v2.3.0] - 2026-10-24

### Added
- **Native `RS256` (RSASSA-PKCS1-v1_5 with SHA-256) Support (`RFC 7518 §3.3`):**
  - Added `AlgRS256` and `NewRS256Verifier(pub, priv, ...opts)` with mathematical keypair cross-validation and `priv.Validate()`.
  - Dynamic per-key signature length resolution (`2048-bit` [256B] to `4096-bit` [512B] keys) across `Verify`, `VerifySplit`, `Sign`, `SignToIOV`, and multi-key `kid` rotation.
  - Strict RFC 7518 §6.3 & FIPS 186-4 public key validation: enforces odd modulus $2048 \le \text{bits}(N) \le 4096$ and odd public exponent $65537 \le E \le 2^{31}-1$.
- **Complete NIST ECDSA Suite: `ES384` (P-384) & `ES512` (P-521) (`RFC 7518 §3.4`):**
  - Added `AlgES384`, `AlgES512`, `NewES384Verifier`, and `NewES512Verifier`.
  - Extended stack-based IEEE P1363 $\leftrightarrow$ ASN.1 DER converters (`encodeP1363ToDERInto` / `decodeDERToP1363`) to support 48-byte (P-384) and 66-byte (P-521) coordinates, including X.690 long-form DER sequence headers (`0x30 0x81 <len>`) when `seqLen >= 128`.
- **Extended Zero-Dependency `ParseJWKS` (`RFC 7517` / `RFC 7518`):**
  - Added ingestion for `"kty": "RSA"` (rejecting non-canonical leading zero bytes on `n` and `e` per RFC 7518 §6.3.1.1) and `"kty": "EC"` with curves `"P-384"` and `"P-521"`.
  - Defensive deep-cloning of `*rsa.PublicKey` and `*ecdsa.PublicKey` `big.Int` scalars (`cloneRSAPublicKey`, `cloneECDSAPublicKey`) to guarantee lock-free immutability.
- **Scratch Workspace Alignment (3,512 Bytes / ~3.5 KB) & Updated Profile-Guided Optimization (`v2/default.pgo`):**
  - Resized `sigBuf` from 96 bytes to 512 bytes (supporting up to RSA-4096 and ES512) and `derBuf` from 72 bytes to 144 bytes with fully inlined `Clear()`.
  - Regenerated `default.pgo` to match the newly optimized function layout and call site offsets for v2.3.0.

### Security & Quality
- Audited against `go-vulndb`, `gosec-rules`, and Project Wycheproof vectors via XERJ.
- **100.0% statement coverage**, `0 B/op, 0 allocs/op` on all symmetric/EdDSA/framework paths, and `0` race conditions under `go test -race`.

---

## [v2.2.0] - 2026-10-24

### Security & Cryptographic Hardening
- **Strict RFC 7518 & Wycheproof P-256 EC Coordinate Validation (`v2/jwks.go`):**
  - Enforced strict 32-octet length checks for NIST P-256 coordinates `x` and `y` per RFC 7518 §6.2.1.2 and §6.2.1.3, rejecting non-canonical leading-zero truncation and arbitrary zero-padded inflation.
  - Validated coordinates against curve geometry via `isValidP256PublicKey`, rejecting points off the curve and the identity point $(0,0)$.
- **Strict RFC 7517 `use` and `key_ops` Consistency (`v2/jwks.go`):**
  - Enforced string type for `"use"` and permitted only `"sig"` and `"enc"`, failing closed on invalid values.
  - Implemented `validateJWKSKeyOps`: requires `"key_ops"` to be a non-empty JSON array of non-empty strings, validates supported operations, and rejects conflicting assignments between `"use"` and `"key_ops"` (e.g. `"use": "sig"` with encryption ops or `"use": "enc"` with signing ops).
  - Skips keys lacking the `"verify"` operation gracefully without failing the JWKS document.
- **Strict Data Types, Algorithm Restrictions & Duplicate `kid` Rejection (`v2/jwks.go`):**
  - Rejects non-string types for `"kty"`, `"kid"`, `"crv"`, `"k"`, `"x"`, and `"y"`.
  - Rejects duplicate `"kid"` values within the same JWKS document to prevent key shadowing attacks.
  - Validates `"alg"` cross-compatibility against key type, rejecting `"none"`, empty strings, and mismatched algorithm pairs.
  - Rejects embedded carriage returns (`\r`) and newlines (`\n`) in Base64URL-encoded key materials.
- **Defensive ECDSA Public Key Cloning (`v2/jwt.go`):**
  - Defensively clones `ecdsa.PublicKey` coordinates (`X` and `Y` `big.Int`s) during Verifier initialization and dynamic key compilation (`cloneECDSAPublicKey`), guaranteeing thread-safe immutability against external mutation races.
- **HTTP Header Injection & Response Splitting Prevention in ForwardAuth (`v2/middleware.go`):**
  - Added `hasHTTPHeaderControlByte` in `ForwardAuthHandler`: inspects `Username()` and `Subject()` claims, rejecting tokens with ASCII control bytes (`< 0x20` or `0x7f`, such as `\r`, `\n`, `\x00`) with HTTP 401 Unauthorized before setting `X-Auth-User` or `X-Auth-Sub` headers upstream.

### Performance & Micro-Optimizations
- **Bounds Check Elimination (BCE) & SWAR Comparisons (`v2/scanner.go`):**
  - Applied Bounds Check Elimination (BCE) assertions in critical JSON unescaping and escaping loops, eliminating slice index bounds checks in compiled assembly.
  - Implemented fast whitespace lookup table (`wsLut`) and SWAR / LittleEndian word comparisons for delimiter scans.
  - Separated fast-paths from slow-paths in `TrimJSONObject` and `TrimJSONArray` (`trimJSONObjectSlow` / `trimJSONArraySlow` marked `//go:noinline`), allowing fast-paths to inline fully within the compiler budget.
- **Power-of-2 Bitwise Masking in `WorkerScratchGroup` (`v2/worker.go`):**
  - Replaced modulo operator (`workerID % len(workers)`) with bitwise masking (`workerID & w.mask`) where `w.mask = uint32(n - 1)`, reducing worker routing overhead to a single CPU cycle.
- **Stack-Allocated ES256 Split Verification (`v2/split.go`):**
  - Replaced heap-allocating `sha256.New()` with stack-based `sha256.Sum256` in `verifySplitSignatureAndDecodePayload`, ensuring zero heap allocations on split buffer verification.
  - Short-circuited `stitchSigningInput` to return `part1` directly when `len(part2) == 0`.
- **Parametrized IEEE P1363 <-> ASN.1 DER Converters (`v2/jwt.go`):**
  - Parametrized stack-based conversion by coordinate length (`coordLen := len(dst) / 2`), supporting P-256 (32 bytes) and P-384 (48 bytes) with zero heap allocations.
- **Updated Profile-Guided Optimization (`v2/default.pgo`):**
  - Regenerated `default.pgo` to match the newly optimized function layout and call site offsets, reducing parallel verification latency to ~145 ns/op.

---

## [v2.1.3] - 2026-10-22

### Documentation
- **Iterator Allocation and Panic Semantics (`v2/iter.go`, `v2/README.md`):**
  - Explicitly documented compiler-dependent allocation characteristics: `Iter` and `IterSplit` allocate ~3 allocs/op in Go 1.23 and 0 allocs/op in Go 1.24+, while `IterWithScratch` and `IterSplitWithScratch` guarantee `0 B/op, 0 allocs/op` across all supported Go versions (Go 1.23+).
  - Documented non-defer panic recovery behavior in `Iter` / `IterSplit`: if the iteration loop panics, the leased scratch is abandoned to the garbage collector rather than recycled to `sync.Pool`.
  - Clarified RFC 8259 top-level header parsing boundaries in READMEs: validates separators, numbers, and JSON structure, without validating inner string literal contents.
- **Changelog Precision:**
  - Corrected description of `ParseJWKS` buffer protection to reference temporary copies instead of stack buffers.

---

## [v2.1.2] - 2026-10-22

### Fixed
- **Eliminate Heap Escape in `IterSplitWithScratch` on Go 1.23 (`v2/iter.go`):**
  - Directly decoded split payloads in `IterSplitWithScratch` without nested generator closure calls, preventing the `yield` function from escaping to heap under Go 1.23 compiler escape analysis.
  - Ensures both `IterWithScratch` and `IterSplitWithScratch` strictly achieve `0 B/op, 0 allocs/op` across all supported Go versions (Go 1.23+).
  - Added explicit zero-allocation assertions for `IterWithScratch` and `IterSplitWithScratch` in `TestZeroAllocations`.

---

## [v2.1.1] - 2026-10-22

### Security & Hardening
- **Restored RFC 8259 JSON Scanner Rigor (`v2/scanner.go`):**
  - Restored strict number format verification in `scanJSONValue`: rejects leading zeroes (e.g. `01`), trailing decimal points (`1.`), standalone minus (`-`), unclosed exponents (`1e`, `1e+`), leading plus (`+1`), and missing integer zero (`.5`).
  - Restored nesting depth limit (32 levels) and stack-allocated bracket matching `[32]byte` to catch mismatched braces/brackets (e.g. `[1}]`).
  - Restored rejection of malformed scalar tokens (e.g. `truee`, `nulll`).
- **Input Buffer Immutability in `ParseJWKS` (`v2/jwks.go`):**
  - Eliminated caller input buffer mutation by copying escaped `kid` values into a temporary copy buffer prior to in-place unescaping, protecting cached JWKS response payloads.
- **RFC 7517 §5 JWKS Interoperability (`v2/jwks.go`):**
  - Gracefully ignores unsupported key types (such as RSA `kty: "RSA"`) and encryption keys (`use: "enc"`), failing closed only when the resulting key set is empty.

### Fixed
- **`VerifySplit` Error Uniformity on Corrupted Tokens (`v2/split.go`):**
  - Aligned error returned for tokens containing unexpected extra dots in `head` (Case 1) with `Verify`, returning `ErrInvalidToken` instead of `ErrInvalidHeader`.
- **RFC 7235 / RFC 6750 Case-Insensitive Bearer Matching (`v2/middleware.go`):**
  - Accepted lowercase `bearer ` prefix in `VerifyBearer` alongside `Bearer `.
- **RFC 7235 Compliance in Reverse Proxy Middleware (`v2/middleware.go`):**
  - Added `WWW-Authenticate: Bearer error="unauthorized"` header to HTTP 401 responses generated by `ForwardAuthHandler`.

### Changed & Deprecated
- **Zero Allocations on Go 1.24+ for `Iter` and `IterSplit` (`v2/iter.go`):**
  - Removed `defer` on critical loop execution in `Iter` and `IterSplit`, eliminating closure escape overhead to achieve 0 allocs/op on Go 1.24+ (~3 allocs/op on Go 1.23).
- **Deprecations (`v2/`):**
  - Marked redundant helpers `NewSecureVerifier`, `TrySign`, and `TrySignClaims` with standard `// Deprecated:` doc comments in favor of `New`, `Sign`, and `SignClaims`.
- **Documentation & Security Policy:**
  - Updated `SECURITY.md` supported versions table to include `2.1.x`.
  - Documented strict `kid` requirement in migration guide: tokens containing `kid` return `ErrUnknownKeyID` when no `Keys` are registered in the verifier.

---

## [v2.1.0] - 2026-10-21

### Added
- **Ring-Buffer Range-Over-Func Iterators (`IterSplit` / `VerifySplitAndIterate`):**
  - `VerifySplitAndIterate(head, tail, now, seq)`: atomically verifies fragmented tokens across circular ring buffers (`gnet`, `evio`, `epoll`) and yields key-value JSON claims via Go 1.23 `iter.Seq2[JSONProp, error]` with 0 heap allocations.
  - `IterSplit(head, tail, now)` and `IterSplitWithScratch(head, tail, now, scratch)`: direct iterator over fragmented ring-buffer tokens.
  - Ergonomic `IterWithScratch(token, now, scratch)` for contiguous tokens using caller-pinned workspaces.
- **Lock-Free Dynamic Key Rotation (`UpdateKeys`):**
  - `v.UpdateKeys(keys []Key)`: thread-safe, lock-free key rotation in live production traffic using atomic pointer swapping (`atomic.Pointer[keySet]`).
  - Scratch state automatically detects key rotation version changes (`keyVersion`) without CAS locking or memory allocations, refreshing cached HMAC signers safely.
- **Native RFC 7517 JWKS Parser (`ParseJWKS` / `UpdateKeysFromJWKS`):**
  - Pure Go, zero-dependency JWKS parser supporting `oct` (HS256/384/512), `OKP` (Ed25519), and `EC` (ES256 P-256).
  - Performs cryptographic curve checks (`elliptic.P256().IsOnCurve`), key lengths, and base64url decoding with strict error boundaries.
  - `v.UpdateKeysFromJWKS(jwksJSON []byte)`: directly ingest JWKS from OIDC discovery endpoints and rotate keys in place without service interruption.
- **Turnkey Reverse Proxy Auth Middleware (`ForwardAuthHandler`):**
  - Native turnkey HTTP handler for edge authentication subrequests in Nginx (`ngx_http_auth_request_module`) and Traefik `ForwardAuth`.
  - Supports token extraction from `Authorization: Bearer <token>`, custom headers (e.g. `X-Auth-Token`), or HTTP cookies.
  - On valid authentication (HTTP 200), automatically sets downstream identity headers (`X-Auth-User`, `X-Auth-Sub`) for upstream request injection with optional `PopulateHeaders` callback.

---

## [v2.0.2] - 2026-10-21

### Style & CI
- **Code Formatting (`v2/scanner.go`):** Aligned `v2/scanner.go` with standard `gofmt` to satisfy strict CI formatting quality gates.

---

## [v2.0.1] - 2026-10-21

### Security & Hardening
- **Canonical Token Enforcement in `VerifySplit` (`v2/split.go`):** Rejects embedded `\r` and `\n` characters in `head` and `tail` within `verifySplitSignatureAndDecodePayload`, closing lenient whitespace acceptance by the base64 decoder and guaranteeing a single canonical token representation across fragmented ring buffers.

### Added
- **`ErrInsecureSecret` Sentinel Alias (`v2/errors.go`):** Added `ErrInsecureSecret = ErrInvalidConfig` alias aligning with RFC 7518 documentation references and allowing callers to query either error identifier with `errors.Is`.
- **`JSONProp` Ergonomic Accessors (`v2/scanner.go`):** Added `.Value() []byte` and `.IsString() bool` methods on `JSONProp` as aliases for `Val` and `IsStr`.
- **Bilingual Documentation for `examples/gnet`:** Added complete Portuguese guide [`examples/gnet/README_pt-BR.md`](examples/gnet/README_pt-BR.md) alongside English [`examples/gnet/README.md`](examples/gnet/README.md) with language switcher links.

### Fixed
- **Documentation Snippet Precision:** Corrected `v2/README.md` and `v2/README_pt-BR.md` `Iter` code examples from `prop.Value` / `prop.IsString` to `prop.Val` / `prop.IsStr`.
- **Packaging Hygiene:** Removed compiled `zerojwt.test` binary artifact from local directories to avoid inclusion in zip or distribution archives.

---

## [v1.3.2] - 2026-10-21

### Documentation & Deprecation
- **Formal v2 Migration Banner:** Added `Deprecated: Use github.com/KaikeGM/zerojwt/v2 instead.` to root package documentation in `jwt.go` to display official migration banner on `pkg.go.dev` and in Go IDEs/toolchain.
- **Absolute pkg.go.dev Redirection:** Updated root `README.md` and `README_pt-BR.md` banner links from relative paths to canonical `https://pkg.go.dev/github.com/KaikeGM/zerojwt/v2`.

---

## [v2.0.0] - 2026-10-21

### Added
- **Dedicated Major Module (`github.com/KaikeGM/zerojwt/v2`):** Isolated v2 module under `v2/go.mod` maintaining backward compatibility for v1 while eliminating legacy dual-API debt.
- **Single Unified `Claims` Struct (1016 Bytes):** Replaces `Claims` and `ClaimsLarge` with a unified struct conforming strictly to OIDC Core 1.0 §2 (`sub` expanded to 256 bytes, supporting up to 255 ASCII characters). 8-byte CPU word alignment guarantees `0 B/op, 0 allocs/op` on all HS256 and Ed25519 verification paths.
- **Secure-by-Default Constructor (`New(secret, ...Options)`):** Strictly secure out of the box per RFC 7518 §3.2 (rejects short secrets with `ErrInsecureSecret`) and OIDC Core 1.0 §3.1.3.7 / RFC 9068 §2.2 (rejects tokens missing `exp` with `ErrMissingExp`). Legacy migration flags `AllowShortSecret` and `AllowMissingExp` provided.
- **Keypair Cross-Validation at Initialization:** `NewEd25519Verifier` and `NewES256Verifier` cryptographically validate that public and private keys match at boot with `ErrMismatchedKeyPair`, and enforce scalar bounds $1 \le D < N$ per RFC 7518 §3.4.
- **Idiomatic Append Signing with Zero-Alloc Rollback:** `Sign`, `SignClaims`, and `SignBuilder` return `([]byte, error)` following Go's `append` idiom, automatically rolling back `dst` to its initial length upon failure without partial output corruption.
- **Generic `AppendEscapedJSON[S ~string | ~[]byte]`:** Format dynamic user strings and byte slices (e.g. 36-byte UUIDs) into JSON payloads with zero heap allocations.
- **Atomic Verification Iterator (`Iter`):** Leverages Go 1.23 standard `iter.Seq2[JSONProp, error]`. Guarantees atomic verification: claims are yielded if and only if the token is 100% cryptographically verified and structurally valid.
- **Event-Driven Network Primitives (`gnet`, `evio`, `epoll`):**
  - **`VerifySplit` / `VerifySplitWithScratch`:** Validates tokens fragmented across non-contiguous circular ring buffers (`head` + `tail`) with 0 heap allocations via 4-byte stack quantum seam stitching and direct HMAC streaming (~11.3 ns delta).
  - **`WorkerScratchGroup` & `PaddedScratch`:** Worker-pinned workspace array with 64-byte CPU cache-line padding, eliminating `sync.Pool` CAS lock contention and L1/L2 cache false sharing (~158.4 ns/op parallel verification).
  - **`SignToIOV` / `SignClaimsToIOV`:** Vectorized scatter/gather signing for `unix.Writev` / `gnet.Conn.Writev` via stack `*[2][]byte`, bypassing the 37-byte header copy.
- **Runnable `gnet` Gateway Sample (`examples/gnet/`):** Full end-to-end event-driven TCP authentication gateway demonstrating `WorkerScratchGroup`, `VerifySplit`, and `SignToIOV` with 10 concurrent clients under race detection.
- **Profile-Guided Optimization Profile (`v2/default.pgo`):** Generated from intensive microbenchmarks to enable aggressive compiler inlining across new hot paths.

### Changed
- **Breaking:** Module path changed to `github.com/KaikeGM/zerojwt/v2`.
- **Breaking:** `NewVerifier` replaced by `zerojwt.New(secret, ...Options)`.
- **Breaking:** `ClaimsLarge` removed and consolidated into unified `Claims`.
- **Breaking:** `Sign` signature updated to `Sign(dst, pl) ([]byte, error)`.
- **Breaking:** Expiration (`exp`) claim is now required by default (opt-out via `Options{AllowMissingExp: true}`).

---

## [v1.3.1] - 2026-10-20

### Documentation
- **Normative Citation Correction:** Corrected RFC 9068 section reference from §2.2.1 to §2.2 ("Data Structure") across godoc (`jwt.go`), `README.md`, `README_pt-BR.md`, and `CHANGELOG.md`.
- **Top-Level Header Separator Precision:** Clarified that strict RFC 8259 comma and separator enforcement applies specifically to top-level header properties in `validateHeader`.
- **Claims Asymmetry Clarification:** Documented that `TrySignClaims` reduces issuer/verifier asymmetry by imposing a 256-byte ceiling (`ClaimsLarge` limit); tokens with `sub` between 65B and 256B require `VerifyLarge` as standard `Claims` allocates a 64-byte buffer.
- **ES256 Allocation Range:** Documented in READMEs that `crypto/ecdsa` allocations vary with Go runtime version (~8–10 allocs/op verify, ~33–67 allocs/op sign).

---

## [v1.3.0] - 2026-10-20

### Added
- **Production Secure Constructors (`NewSecureVerifier`, `NewSecureVerifierWithOptions`, `SecureOptions`):** Added first-class constructors aligned with modern identity standards (OIDC Core 1.0 §3.1.3.7, OAuth 2.0 RFC 9068 §2.2, and RFC 7518 §3.2) enforcing `RequireExp: true` and `StrictSecretLength: true` ($\ge 32$ bytes for HS256) with typed error initialization (`(*Verifier, error)`).
- **Typed Signing APIs (`TrySign`, `TrySignWithScratch`, `TrySignClaims`, `TrySignClaimsWithScratch`):** Added direct signing methods returning `([]byte, error)` with explicit sentinel errors (`ErrPayloadTooLarge`, `ErrMissingExp`, `ErrNoSigningKey`, `ErrSigningFailed`, `ErrInvalidPayload`) while guaranteeing `0 B/op, 0 allocs/op`.
- **`ErrSigningFailed` Sentinel Error:** Added distinct sentinel error for cryptographic signing failures (differentiating signing runtime failures from verification failures).
- **RFC 8259 Differential Testing Suite (`scanner_rfc8259_diff_test.go`):** Documented and tested equivalence against standard JSON as well as intentional payload lexer tolerances for maximum streaming performance.

### Security & Hardening
- **Strict Pre-Authentication Top-Level Header Parsing:** Enforced strict RFC 8259 comma and separator syntax for top-level properties in `validateHeader` before signature verification, strictly rejecting missing commas, duplicate commas (`,,`), trailing commas (`,}`), and non-object header structures.
- **ECDSA P-256 Private Scalar Mathematical Validation:** Added mathematical verification ($1 \le D < N$) for NIST P-256 private keys in `validateConfig` to reject invalid scalars at initialization.
- **Claims Boundary Enforcement in `SignClaims`:** Enforced `sub` $\le 256$ bytes (matching `ClaimsLarge` capacity) and `username` $\le 256$ bytes in `TrySignClaims` / `SignClaims`, reducing issuer/verifier asymmetry on claim sizes.

### Refactored
- **Single Path of Truth for Signing:** Re-architected `Sign`, `SignWithScratch`, `SignHS256`, `SignHS256WithScratch`, and `SignClaims` as thin wrappers over `TrySign*`, eliminating duplicate code paths and ensuring consistent error guarding across all entry points.

---

## [v1.2.4] - 2026-10-20

### Fixed
- **Payload Size Enforcement on Signing (`Sign`, `SignWithScratch`, `SignClaims`, `SignHS256`):** Added `len(payloadJSON) > v.maxPayloadSize` guard to eliminate issuer/verifier asymmetry where a verifier could sign tokens exceeding its own `MaxPayloadSize` that it would subsequently reject upon verification (`ErrPayloadTooLarge`). Oversized payloads now safely return `nil` without modifying destination buffers.
- **Fair Benchmark Clock Evaluation:** Normalized verification benchmarks in `benchmarks/benchmarks_test.go` and `bench_test.go` to invoke `time.Now().Unix()` on each iteration, eliminating unearned ~18ns vDSO clock advantages and leveling measurement against competitor libraries that sample system time internally.
- **Benchmark Column Precision:** Renamed the "Latency" column in benchmark tables to "Avg Time / op" ("Tempo Médio / op" in Portuguese) for standard Go microbenchmark nomenclature.

### Documentation
- **Explicit `Sign*` Failure Handling:** Documented that `Sign`, `SignWithScratch`, and `SignClaims` return `nil` on failure (e.g. when payload size exceeds `MaxPayloadSize`, signing key is missing, or `RequireExp` is violated) and reminded callers to check return values or use `NewSigner()` for explicit typed errors.
- **Production `RequireExp` Recommendation:** Added callouts in both `README.md` and `README_pt-BR.md` emphasizing configuring `RequireExp: true` in production `Options{}` so tokens omitting `exp` are rejected immediately (`ErrMissingExp`).

---

## [v1.2.3] - 2026-10-20

### Fixed
- **Deterministic ES256 DER Test Coverage:** Added fixed edge-vector test suite (`es256_der_test.go`) covering all high-bit and leading-zero DER/P1363 branches, eliminating coverage gate flakiness and guaranteeing 100.0% statement coverage across all test runs.
- **`Destroy()` Changelog Attribution:** Corrected v1.1.0 changelog entry to reflect that `Destroy()` was changed to fail closed rather than introduced.

---

## [v1.2.2] - 2026-10-20

### Fixed
- **CI Windows Runner Shell Execution:** Resolved syntax failures on `windows-latest` by configuring `defaults: run: shell: bash` across matrix jobs and moving the `gofmt` verification script to the Ubuntu quality gate.
- **`go.mod` Retract Notice:** Translated retraction comments to English (`Accepted forged tokens (empty HMAC key); fixed in v1.1.0`) for global toolchain visibility.
- **Documentation Phrasing:** Clarified version requirements to "Go 1.23 or newer" in `README.md` and "Go 1.23 ou superior" in `README_pt-BR.md`.
- **Static Analysis Gate:** Added `go vet ./...` to the CI workflow matrix.

---

## [v1.2.1] - 2026-10-20

### Added
- **`go.mod` Retractions:** Formally retracted vulnerable legacy versions `v1.0.0` and `v1.0.1` via `retract` directives in `go.mod`.
- **Go 1.23+ Standardized Support:** Standardized `go.mod` and the entire CI matrix (Ubuntu, macOS, Windows) across Go 1.23 through Go 1.27+.
- **CI Automated `gofmt` & `go vet` Enforcement:** Added steps in GitHub Actions workflow to verify formatting with `gofmt -l` and static analysis with `go vet`.

### Fixed
- **Scanner & Iterator Documentation:** Corrected docstrings on `NextJSONProp`, `NextArrayElement`, `ArrayElements`, and `ObjectProps` to document non-destructive behavior (raw escaped strings returned without mutating the underlying buffer).
- **Code Formatting:** Formatted `builder.go` and `coverage_test.go` with `gofmt`.

---

## [v1.2.0] - 2026-10-19

### ⚠️ Breaking Changes & Migration Guide

1. **Non-Destructive String Lexing in `scanner.go` & `iter.go`:**
   - **Previous behavior:** `NextJSONProp` and `NextArrayElement` called `UnescapeJSONInPlace` internally, mutating the underlying byte slice in-place. If the buffer was read a second time or reused, string values were corrupted.
   - **New behavior:** `NextJSONProp` and `NextArrayElement` return non-destructive slice references into the buffer with surrounding quotes stripped, but keeping escape sequences (e.g. `\"`, `\n`, `\uXXXX`) as-is.
   - **Migration:** If your application relies on decoded string values, call `zerojwt.UnescapeJSONInPlace(val)` explicitly on string slices (`if isStr`).

2. **Strict Sub-Second Leeway Validation:**
   - **Previous behavior:** Specifying `Leeway` under 1 second (e.g. `500 * time.Millisecond`) was silently truncated to `0s` due to integer division.
   - **New behavior:** `Options.Leeway` strictly requires whole seconds ($\ge 1\text{s}$) or `0`. Values between `0 < Leeway < 1s` are rejected with `ErrInvalidConfig` at initialization.

### Added
- **Go 1.23+ Range-Over-Func Iterators (`iter.go`):**
  - `ArrayElements(rawArray []byte, errOut ...*error) iter.Seq2[[]byte, bool]`
  - `ObjectProps(rawObject []byte, errOut ...*error) iter.Seq2[[]byte, []byte]`
  - `ObjectProperties(rawObject []byte, errOut ...*error) iter.Seq[JSONProp]`
  - All iterators operate at **~18M–19M ops/s** with guaranteed **`0 B/op` and `0 allocs/op`**.
- **Iterators Strict Syntax Error Handling:** Optional `*error` pointer argument to detect truncated or invalid JSON syntax.
- **SignBuilder Resource Safety:** Added `(*SignBuilder).Discard()` to return internal `Scratch` to `sync.Pool` if an error occurs before `Sign()`.
- **Expanded Integer Parsing:** `ParsePositiveInt` expanded to parse up to 19 decimal digits within the positive `int64` range (supporting 64-bit Snowflake IDs).
- **Comprehensive Brazilian Portuguese Documentation:** Added `README_pt-BR.md` alongside `README.md`.

### Fixed
- **JSON Parameter Pollution Protection:** `parseStandardClaims`, `parseLargeClaims`, and `validateHeader` now reject tokens containing duplicate registered claims (`sub`, `iss`, `aud`, `exp`, `nbf`, `iat`, `jti`, `alg`, `typ`, `kid`).
- **Throughput Calculation Accuracy:** Corrected benchmark throughput metrics in documentation from iteration counts to true throughput ($10^9 / \text{ns/op}$).
- **100.0% Statement Test Coverage:** Reached 100.0% verified statement coverage across all packages and functions.

---

## [v1.1.2] - 2026-10-19

### Fixed
- **macOS CI Clock Jitter Tolerance:** Broadened leeway test margin in `TestIndustrialSuite` to tolerate hypervisor timer drift on virtualized Apple Silicon runners.

---

## [v1.1.1] - 2026-10-19

### Added
- **Isolated Competitor Benchmark Suite:** Added reproducible benchmarks in `benchmarks/` comparing `zerojwt` with `golang-jwt/jwt/v5`, `lestrrat-go/jwx/v2`, and `kataras/jwt`.

---

## [v1.1.0] - 2026-10-19

### ⚠️ Security & Breaking Changes
- **Fail-Fast Configuration:** Constructors (`NewVerifier`, `NewEd25519Verifier`, etc.) panic when supplied with unusable key material (e.g. empty secrets, mismatched curves). Added `TryNewVerifier` for non-panicking initialization.
- **Key Rotation Validation:** Duplicate key IDs in `Options.Keys` and keys without cryptographic material for the selected algorithm are now rejected at startup (`ErrInvalidConfig`).
- **Enforce `exp` Requirement (`RequireExp`):** Added `RequireExp` option to reject tokens without an `exp` claim, and enforce that `SignClaims`/`SignBuilder` refuse to omit expiration.
- **RFC 7518 Minimum Secret Length (`StrictSecretLength`):** Added `StrictSecretLength` option to enforce 32/48/64 byte minimum key lengths for HS256/384/512.
- **Signing Capability Inspection (`CanSign`):** Added `(*Verifier).CanSign() bool` reporting whether the verifier holds a private signing key. On verify-only nodes, `Sign*` returns `nil` and `SignBuilder.Sign` returns `ErrNoSigningKey`.
- **Fail-Closed Memory Hygiene (`Destroy`):** Changed `(*Verifier).Destroy()` to permanently transition the verifier into a fail-closed state (`ErrVerifierDestroyed`) in addition to wiping internal secrets.
- **Strict Base64URL and Whitespace Validation:** Non-canonical trailing bits and whitespace (`\r`, `\n`) in token strings are strictly rejected.
- **Header `crit` Rejection:** Tokens specifying unsupported `crit` headers are rejected in accordance with RFC 7515 §4.1.11.

---

## [v1.0.1] - 2026-10-19 [RETRACTED]

> **Retracted:** Contained key validation flaws where empty secrets were accepted. Superseded by `v1.1.0+`.

---

## [v1.0.0] - 2026-10-19 [RETRACTED]

> **Retracted:** Initial release. Superseded by `v1.1.0+`.
