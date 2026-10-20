# Changelog

All notable changes to `zerojwt` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [v1.2.1] - 2026-10-20

### Added
- **`go.mod` Retractions:** Formally retracted vulnerable legacy versions `v1.0.0` and `v1.0.1` via `retract` directives in `go.mod`.
- **Go 1.23 to 1.27+ Standardized Support:** Standardized `go.mod` and the entire CI matrix (Ubuntu, macOS, Windows) to run across Go 1.23 through Go 1.27+.
- **CI Automated `gofmt` Enforcement:** Added a step in GitHub Actions workflow to verify formatting across all files with `gofmt -l`.

### Fixed
- **Scanner & Iterator Documentation:** Corrected docstrings on `NextJSONProp`, `NextArrayElement`, `ArrayElements`, and `ObjectProps` to document the non-destructive behavior (raw escaped strings returned without mutating the underlying buffer).
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

3. **Key Rotation Configuration Validation:**
   - Duplicate key IDs in `Options.Keys` or keys without matching cryptographic material for the selected algorithm are now rejected at startup.

### Added
- **Go 1.23+ Range-Over-Func Iterators (`iter.go`):**
  - `ArrayElements(rawArray []byte, errOut ...*error) iter.Seq2[[]byte, bool]`
  - `ObjectProps(rawObject []byte, errOut ...*error) iter.Seq2[[]byte, []byte]`
  - `ObjectProperties(rawObject []byte, errOut ...*error) iter.Seq[JSONProp]`
  - All iterators operate at **~18M–19M ops/s** with guaranteed **`0 B/op` and `0 allocs/op`**.
- **Iterators Strict Syntax Error Handling:** Optional `*error` pointer argument to detect truncated or invalid JSON syntax.
- **SignBuilder Resource Safety:** Added `(*SignBuilder).Discard()` to return internal `Scratch` to `sync.Pool` if an error occurs before `Sign()`.
- **Expanded Integer Parsing:** `ParsePositiveInt` expanded to parse up to 19 digits for 64-bit unsigned Snowflake IDs.
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
- **Strict Base64URL and Whitespace Validation:** Non-canonical trailing bits and whitespace (`\r`, `\n`) in token strings are strictly rejected.
- **Header `crit` Rejection:** Tokens specifying unsupported `crit` headers are rejected in accordance with RFC 7515 §4.1.11.
- **Verify-Only Safety:** `Sign*` methods return `nil` and `SignBuilder.Sign` returns `ErrNoSigningKey` on verifiers without private signing keys.

---

## [v1.0.1] - 2026-10-19 [RETRACTED]

> **Retracted:** Contained key validation flaws where empty secrets were accepted. Superseded by `v1.1.0+`.

---

## [v1.0.0] - 2026-10-19 [RETRACTED]

> **Retracted:** Initial release. Superseded by `v1.1.0+`.
