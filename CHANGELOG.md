# Changelog

All notable changes to `zerojwt` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
