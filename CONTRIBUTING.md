# Contributing to zerojwt

First off, thank you for considering contributing to `zerojwt`! It's people like you that help keep `zerojwt` fast, secure, and reliable.

## Code of Conduct

This project and everyone participating in it is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

---

## Architectural Principles & Invariants

`zerojwt` is engineered for extreme throughput and latency-critical environments. When contributing code, please keep the following hard invariants in mind:

1. **Zero-Allocation Guarantee (v2):**
   - The hot verification paths (`VerifyWithScratch`, `IterWithScratch`, `IterSplitWithScratch`) must strictly maintain **`0 B/op` and `0 allocs/op`**.
   - No slice growth or heap escapes are allowed in the validation and parser loops.
   - Always run `-benchmem` before and after changes.

2. **Strict RFC Conformance:**
   - JWT validation strictly follows **RFC 7519**.
   - JSON parsing strictly enforces **RFC 8259** grammar (unescaped controls, surrogate pairs, numeric formats, whitespace, and structural delimiters).
   - Under no circumstances should security checks be relaxed for convenience.

3. **Concurrency & Thread Safety:**
   - `Verifier` and `JWKS` instances must remain safe for concurrent reads.
   - Key rotation in v2 uses lock-free atomic pointer swaps (`atomic.Pointer[keySet]`). Do not introduce mutexes on the hot verification paths.

---

## Development Setup & Workflow

### Prerequisites
- Go 1.23 or newer (required for v2 iterators and modern compiler optimizations).

### Running Tests

Run the full test suite with the race detector enabled across both modules:

```bash
# Test root (v1)
go test -v -race ./...

# Test v2
cd v2
go test -v -race ./...
```

All tests must pass with 100% test coverage preserved on security-critical logic.

### Benchmarking & Allocation Verification

Verify that your changes introduce zero regressions in throughput and zero heap allocations:

```bash
cd v2
go test -bench=. -benchmem -run=^#
```

Ensure allocations remain `0 allocs/op` for all `*WithScratch` benchmarks.

### Fuzz Testing

If you modify `scanner.go`, `jwt.go`, or any decoding routine, run the fuzz test suite:

```bash
cd v2
go test -fuzz=FuzzScanner -fuzztime=1m ./...
go test -fuzz=FuzzHeaderValidation -fuzztime=1m ./...
```

### Formatting and Linting

Ensure all code follows standard Go formatting and idioms:

```bash
gofmt -s -w .
go vet ./...
```

---

## Submitting a Pull Request

1. **Fork and branch:** Create a descriptive branch from `main` (e.g. `feat/faster-base64`, `fix/scanner-surrogate`).
2. **Commit messages:** We recommend following [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` New capability or endpoint.
   - `fix:` Bug fix or security hardening.
   - `perf:` Performance enhancement with benchmark proof.
   - `docs:` Documentation improvements.
   - `test:` Adding or updating tests.
3. **Include tests:** Every bug fix or feature must include regression unit tests.
4. **Open PR:** Submit your pull request against the `main` branch with a clear description of the problem solved and benchmark diffs if applicable.

---

## Security Disclosures

If you discover a security vulnerability, please do **NOT** open a public issue. Follow our responsible disclosure process outlined in [SECURITY.md](SECURITY.md).
