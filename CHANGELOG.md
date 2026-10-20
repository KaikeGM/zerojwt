# Changelog

All notable changes to `zerojwt` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- **Fail-Closed Memory Hygiene (`Destroy`):** Added `(*Verifier).Destroy()` to wipe internal secrets and permanently transition the verifier into a fail-closed state (`ErrVerifierDestroyed`).
- **Strict Base64URL and Whitespace Validation:** Non-canonical trailing bits and whitespace (`\r`, `\n`) in token strings are strictly rejected.
- **Header `crit` Rejection:** Tokens specifying unsupported `crit` headers are rejected in accordance with RFC 7515 §4.1.11.

---

## [v1.0.1] - 2026-10-19 [RETRACTED]

> **Retracted:** Contained key validation flaws where empty secrets were accepted. Superseded by `v1.1.0+`.

---

## [v1.0.0] - 2026-10-19 [RETRACTED]

> **Retracted:** Initial release. Superseded by `v1.1.0+`.
