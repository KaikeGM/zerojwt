// Package zerojwt provides an ultra-fast, zero-allocation (0 B/op, 0 allocs/op)
// JWT validator and signer in pure Go supporting HS256, HS384, HS512, EdDSA (Ed25519), and ES256.
package zerojwt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Algorithm represents a supported JWS cryptographic algorithm (RFC 7518 / RFC 8037).
type Algorithm string

const (
	AlgHS256 Algorithm = "HS256"
	AlgHS384 Algorithm = "HS384"
	AlgHS512 Algorithm = "HS512"
	AlgEdDSA Algorithm = "EdDSA"
	AlgES256 Algorithm = "ES256"
)

const (
	// MaxHeaderSize is the default maximum decoded byte length of a JWT header in zero-alloc mode.
	MaxHeaderSize = 128
	// MaxPayloadSize is the default maximum decoded byte length of a JWT payload in zero-alloc mode.
	MaxPayloadSize = 1024

	// Pre-encoded Base64URL headers for `{"alg":"<ALG>","typ":"JWT"}` followed by '.'
	encodedHS256HeaderDot = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
	encodedHS384HeaderDot = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9."
	encodedHS512HeaderDot = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9."
	encodedEdDSAHeaderDot = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9."
	encodedES256HeaderDot = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9."
)

// rawURLStrict decodes Base64URL without padding and rejects non-zero trailing
// bits, so every valid token has exactly one accepted string form.
// (Strict() returns a pointer to a copy, so it is built once here to keep
// the verification path allocation-free.)
var rawURLStrict = base64.RawURLEncoding.Strict()

var (
	dotByte      = []byte(".")
	bearerPrefix = []byte("Bearer ")
	algKey       = []byte("alg")
	typKey       = []byte("typ")
	kidKey       = []byte("kid")
	critKey      = []byte("crit")
	jwtVal       = []byte("JWT")
)

// Key represents a named cryptographic key for "kid" (Key ID) rotation in JWT headers.
type Key struct {
	ID            string
	Secret        []byte
	Ed25519Public ed25519.PublicKey
	ECDSAPublic   *ecdsa.PublicKey
}

type compiledKey struct {
	idBytes       []byte
	secret        []byte
	ed25519Public ed25519.PublicKey
	ecdsaPublic   *ecdsa.PublicKey
}

// Options configures algorithm, buffer dimensions, RFC 7519 validation rules,
// key rotation ("kid"), and FIPS/PCI-DSS memory sanitization for a Verifier.
type Options struct {
	// Algorithm selects the JWS algorithm (default: AlgHS256).
	Algorithm Algorithm
	// MaxHeaderSize sets the maximum decoded byte length of a JWT header (default: 128).
	MaxHeaderSize int
	// MaxPayloadSize sets the maximum decoded byte length of a JWT payload (default: 1024).
	MaxPayloadSize int
	// Leeway defines the clock skew tolerance for "exp" and "nbf" validation.
	Leeway time.Duration
	// ExpectedIssuer enforces that the token's "iss" claim matches this value.
	ExpectedIssuer string
	// ExpectedAudience enforces that the token's "aud" claim (string or array) contains this value.
	ExpectedAudience string
	// Keys registers named keys for automatic "kid" header lookup during verification.
	Keys []Key
	// ActiveKeyID embeds `"kid":"<ActiveKeyID>"` in the JWT header when signing tokens.
	ActiveKeyID string
	// Ed25519PublicKey is the 32-byte public key used when Algorithm is AlgEdDSA.
	Ed25519PublicKey ed25519.PublicKey
	// Ed25519PrivateKey is the 64-byte private key used for signing when Algorithm is AlgEdDSA.
	Ed25519PrivateKey ed25519.PrivateKey
	// ECDSAPublicKey is the P-256 public key used when Algorithm is AlgES256.
	ECDSAPublicKey *ecdsa.PublicKey
	// ECDSAPrivateKey is the P-256 private key used for signing when Algorithm is AlgES256.
	ECDSAPrivateKey *ecdsa.PrivateKey
	// ZeroMemory zeroes out sensitive scratch buffers with 0x00 (memclr) after each operation.
	// This is best-effort memory hygiene, not a compliance guarantee.
	ZeroMemory bool
	// RequireExp makes verification fail with ErrMissingExp when a token carries no "exp"
	// claim, and makes SignClaims refuse to sign with exp <= 0. Default: false.
	RequireExp bool
	// StrictSecretLength enforces the RFC 7518 §3.2 minimum HMAC key size
	// (32 bytes for HS256, 48 for HS384, 64 for HS512). Empty keys are always rejected,
	// regardless of this option. Default: false.
	StrictSecretLength bool
}

// Scratch holds reusable buffers and pre-initialized HMAC hashers.
// In multi-goroutine servers, Verifier manages a sync.Pool of Scratch instances automatically.
// In single-threaded event loops (such as gnet with LockOSThread), callers can hold a single
// Scratch instance and call VerifyWithScratch to bypass even sync.Pool overhead.
type Scratch struct {
	mac        hash.Hash
	keyMacs    []hash.Hash
	sigBuf     [96]byte
	sumBuf     [64]byte
	derBuf     [72]byte
	hdrBuf     []byte
	payloadBuf []byte
	hdrArr     [MaxHeaderSize]byte
	payloadArr [MaxPayloadSize]byte
}

func memclr(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Clear zeroes out all internal working buffers in Scratch using runtime memclr.
func (s *Scratch) Clear() {
	memclr(s.sigBuf[:])
	memclr(s.sumBuf[:])
	memclr(s.derBuf[:])
	memclr(s.hdrBuf)
	memclr(s.payloadBuf)
}

// Claims holds standard JWT claims on the caller's stack without heap allocations.
// Its internal fixed buffers own the copied claim bytes, ensuring 100% safety against
// data races even after the internal Scratch buffer returns to the pool.
type Claims struct {
	SubjectID   int64     // Parsed positive integer ID when "sub" is numeric (e.g. "123" -> 123)
	IssuedAt    int64     // "iat" claim (Unix seconds)
	ExpiresAt   int64     // "exp" claim (Unix seconds)
	NotBefore   int64     // "nbf" claim (Unix seconds)
	HasSub      bool      // True if "sub" claim was present
	HasUsername bool      // True if "username" claim was present
	HasIss      bool      // True if "iss" claim was present
	HasAud      bool      // True if "aud" claim was present
	HasJti      bool      // True if "jti" claim was present
	HasExp      bool      // True if "exp" claim was present
	HasNbf      bool      // True if "nbf" claim was present
	HasIat      bool      // True if "iat" claim was present
	subLen      uint8     // Length of Subject in subBuf
	userLen     uint8     // Length of Username in userBuf
	issLen      uint8     // Length of Issuer in issBuf
	audLen      uint8     // Length of Audience in audBuf
	jtiLen      uint8     // Length of JTI in jtiBuf
	subBuf      [64]byte  // Inline stack storage for Subject ("sub")
	userBuf     [128]byte // Inline stack storage for Username ("username")
	issBuf      [64]byte  // Inline stack storage for Issuer ("iss")
	audBuf      [64]byte  // Inline stack storage for Audience ("aud")
	jtiBuf      [64]byte  // Inline stack storage for JWT ID ("jti")
}

// Subject returns the "sub" claim as a byte slice backed by Claims' inline buffer.
func (c *Claims) Subject() []byte { return c.subBuf[:c.subLen] }

// Username returns the "username" claim as a byte slice backed by Claims' inline buffer.
func (c *Claims) Username() []byte { return c.userBuf[:c.userLen] }

// Issuer returns the "iss" claim as a byte slice backed by Claims' inline buffer.
func (c *Claims) Issuer() []byte { return c.issBuf[:c.issLen] }

// Audience returns the primary "aud" claim as a byte slice backed by Claims' inline buffer.
func (c *Claims) Audience() []byte { return c.audBuf[:c.audLen] }

// JTI returns the "jti" (JWT ID) claim as a byte slice backed by Claims' inline buffer.
func (c *Claims) JTI() []byte { return c.jtiBuf[:c.jtiLen] }

// Reset resets length markers and flags for fast reuse without zeroing the underlying byte arrays.
func (c *Claims) Reset() {
	c.SubjectID = 0
	c.IssuedAt = 0
	c.ExpiresAt = 0
	c.NotBefore = 0
	c.HasSub = false
	c.HasUsername = false
	c.HasIss = false
	c.HasAud = false
	c.HasJti = false
	c.HasExp = false
	c.HasNbf = false
	c.HasIat = false
	c.subLen = 0
	c.userLen = 0
	c.issLen = 0
	c.audLen = 0
	c.jtiLen = 0
}

// Clear resets all fields and explicitly zeroes all internal claim buffers with 0x00 (memclr).
func (c *Claims) Clear() {
	c.Reset()
	memclr(c.subBuf[:])
	memclr(c.userBuf[:])
	memclr(c.issBuf[:])
	memclr(c.audBuf[:])
	memclr(c.jtiBuf[:])
}

// ClaimsLarge provides expanded 256-byte inline buffers for deployments where Subject,
// Username, Issuer, Audience, or JTI identifiers exceed 64/128 bytes.
type ClaimsLarge struct {
	SubjectID   int64
	IssuedAt    int64
	ExpiresAt   int64
	NotBefore   int64
	HasSub      bool
	HasUsername bool
	HasIss      bool
	HasAud      bool
	HasJti      bool
	HasExp      bool
	HasNbf      bool
	HasIat      bool
	subLen      uint16
	userLen     uint16
	issLen      uint16
	audLen      uint16
	jtiLen      uint16
	subBuf      [256]byte
	userBuf     [256]byte
	issBuf      [256]byte
	audBuf      [256]byte
	jtiBuf      [256]byte
}

func (c *ClaimsLarge) Subject() []byte  { return c.subBuf[:c.subLen] }
func (c *ClaimsLarge) Username() []byte { return c.userBuf[:c.userLen] }
func (c *ClaimsLarge) Issuer() []byte   { return c.issBuf[:c.issLen] }
func (c *ClaimsLarge) Audience() []byte { return c.audBuf[:c.audLen] }
func (c *ClaimsLarge) JTI() []byte      { return c.jtiBuf[:c.jtiLen] }

func (c *ClaimsLarge) Reset() {
	c.SubjectID = 0
	c.IssuedAt = 0
	c.ExpiresAt = 0
	c.NotBefore = 0
	c.HasSub = false
	c.HasUsername = false
	c.HasIss = false
	c.HasAud = false
	c.HasJti = false
	c.HasExp = false
	c.HasNbf = false
	c.HasIat = false
	c.subLen = 0
	c.userLen = 0
	c.issLen = 0
	c.audLen = 0
	c.jtiLen = 0
}

func (c *ClaimsLarge) Clear() {
	c.Reset()
	memclr(c.subBuf[:])
	memclr(c.userBuf[:])
	memclr(c.issBuf[:])
	memclr(c.audBuf[:])
	memclr(c.jtiBuf[:])
}

// Verifier validates and signs JWT tokens with zero heap allocations (0 B/op, 0 allocs/op).
// A Verifier is 100% safe for concurrent use by multiple goroutines.
type Verifier struct {
	alg              Algorithm
	algBytes         []byte
	sigDecodedLen    int
	sigEncodedLen    int
	encodedHeaderDot string
	secret           []byte
	edPub            ed25519.PublicKey
	edPriv           ed25519.PrivateKey
	ecPub            *ecdsa.PublicKey
	ecPriv           *ecdsa.PrivateKey
	keys             []compiledKey
	leewaySec        int64
	expectedIss      []byte
	expectedAud      []byte
	maxHeaderSize    int
	maxPayloadSize   int
	zeroMemory       bool
	requireExp       bool
	destroyed        atomic.Bool
	pool             sync.Pool
}

// NewVerifier creates a new concurrent-safe HS256 Verifier for the given secret key
// using the default buffer limits (128B header, 1024B payload).
//
// Note: NewVerifier preserves RFC 7519 baseline defaults (RequireExp: false, StrictSecretLength: false).
// For production environments, prefer NewSecureVerifier.
func NewVerifier(secret []byte) *Verifier {
	return NewVerifierWithOptions(secret, Options{Algorithm: AlgHS256})
}

// SecureOptions returns Options preconfigured with strict production security settings
// aligning with OIDC Core 1.0 §3.1.3.7, OAuth 2.0 RFC 9068 §2.2, and RFC 7518 §3.2:
//   - RequireExp: true (rejects tokens without "exp" claim)
//   - StrictSecretLength: true (enforces minimum HMAC key sizes: 32B for HS256, 48B for HS384, 64B for HS512)
//
// Note: StrictSecretLength applies to symmetric HMAC algorithms; asymmetric algorithms
// (EdDSA, ES256) have curve-mandated key sizes enforced directly by mathematical checks.
func SecureOptions() Options {
	return Options{
		Algorithm:          AlgHS256,
		RequireExp:         true,
		StrictSecretLength: true,
	}
}

// NewSecureVerifier creates a new concurrent-safe Verifier preconfigured for production profiles
// (OIDC Core 1.0 §3.1.3.7, RFC 9068 §2.2, RFC 7518 §3.2).
// It enforces RequireExp: true and StrictSecretLength: true (minimum 32 bytes for HS256).
// Returns an error wrapping ErrInvalidConfig if the secret is too short or empty.
func NewSecureVerifier(secret []byte) (*Verifier, error) {
	return TryNewVerifier(secret, SecureOptions())
}

// NewSecureVerifierWithOptions creates a new concurrent-safe Verifier applying RequireExp
// and StrictSecretLength over the caller-provided Options.
func NewSecureVerifierWithOptions(secret []byte, opts Options) (*Verifier, error) {
	opts.RequireExp = true
	opts.StrictSecretLength = true
	return TryNewVerifier(secret, opts)
}

// NewEd25519Verifier creates a new concurrent-safe EdDSA (Ed25519) Verifier.
// For verification-only nodes, priv can be nil.
func NewEd25519Verifier(pub ed25519.PublicKey, priv ed25519.PrivateKey, opts Options) *Verifier {
	opts.Algorithm = AlgEdDSA
	opts.Ed25519PublicKey = pub
	opts.Ed25519PrivateKey = priv
	return NewVerifierWithOptions(nil, opts)
}

// NewES256Verifier creates a new concurrent-safe ECDSA P-256 (ES256) Verifier.
// For verification-only nodes, priv can be nil.
func NewES256Verifier(pub *ecdsa.PublicKey, priv *ecdsa.PrivateKey, opts Options) *Verifier {
	opts.Algorithm = AlgES256
	opts.ECDSAPublicKey = pub
	opts.ECDSAPrivateKey = priv
	return NewVerifierWithOptions(nil, opts)
}

// NewVerifierWithOptions creates a new concurrent-safe Verifier with custom algorithm,
// buffer dimensions, clock skew leeway, issuer/audience rules, and key rotation.
//
// It panics with an error wrapping ErrInvalidConfig when the configuration is unusable
// (empty HMAC secret, a Key without material for the selected algorithm, unknown algorithm,
// wrong key size or curve, ...), so that misconfiguration is caught at startup instead of
// producing a verifier that accepts forged tokens. Use TryNewVerifier to get an error instead.
func NewVerifierWithOptions(secret []byte, opts Options) *Verifier {
	v, err := TryNewVerifier(secret, opts)
	if err != nil {
		panic(err)
	}
	return v
}

// TryNewVerifier is like NewVerifierWithOptions but returns an error wrapping
// ErrInvalidConfig instead of panicking. opts.Algorithm selects the algorithm; for EdDSA and
// ES256 the keys come from the corresponding Options fields and secret is ignored.
func TryNewVerifier(secret []byte, opts Options) (*Verifier, error) {
	alg := opts.Algorithm
	if alg == "" {
		alg = AlgHS256
	}
	if err := validateConfig(secret, alg, opts); err != nil {
		return nil, err
	}
	hdrSize := opts.MaxHeaderSize
	if hdrSize <= 0 {
		hdrSize = MaxHeaderSize
	}
	plSize := opts.MaxPayloadSize
	if plSize <= 0 {
		plSize = MaxPayloadSize
	}

	var sigDecLen, sigEncLen int
	var defaultHdrDot string
	switch alg {
	case AlgHS384:
		sigDecLen = 48
		sigEncLen = 64
		defaultHdrDot = encodedHS384HeaderDot
	case AlgHS512:
		sigDecLen = 64
		sigEncLen = 86
		defaultHdrDot = encodedHS512HeaderDot
	case AlgEdDSA:
		sigDecLen = 64
		sigEncLen = 86
		defaultHdrDot = encodedEdDSAHeaderDot
	case AlgES256:
		sigDecLen = 64
		sigEncLen = 86
		defaultHdrDot = encodedES256HeaderDot
	default:
		alg = AlgHS256
		sigDecLen = 32
		sigEncLen = 43
		defaultHdrDot = encodedHS256HeaderDot
	}

	if opts.ActiveKeyID != "" {
		var hdrJSON []byte
		hdrJSON = append(hdrJSON, `{"alg":"`...)
		hdrJSON = append(hdrJSON, string(alg)...)
		hdrJSON = append(hdrJSON, `","typ":"JWT","kid":`...)
		hdrJSON = AppendEscapedJSONString(hdrJSON, []byte(opts.ActiveKeyID))
		hdrJSON = append(hdrJSON, '}')
		defaultHdrDot = base64.RawURLEncoding.EncodeToString(hdrJSON) + "."
	}

	var cKeys []compiledKey
	if len(opts.Keys) > 0 {
		cKeys = make([]compiledKey, len(opts.Keys))
		for i, k := range opts.Keys {
			cKeys[i] = compiledKey{
				idBytes:       []byte(k.ID),
				secret:        append([]byte(nil), k.Secret...),
				ed25519Public: append(ed25519.PublicKey(nil), k.Ed25519Public...),
				ecdsaPublic:   k.ECDSAPublic,
			}
		}
	}

	// A signer configured with only a private key can still verify its own tokens.
	edPub := opts.Ed25519PublicKey
	if len(edPub) == 0 && len(opts.Ed25519PrivateKey) == ed25519.PrivateKeySize {
		edPub = opts.Ed25519PrivateKey.Public().(ed25519.PublicKey)
	}
	ecPub := opts.ECDSAPublicKey
	if ecPub == nil && opts.ECDSAPrivateKey != nil {
		ecPub = &opts.ECDSAPrivateKey.PublicKey
	}

	v := &Verifier{
		alg:              alg,
		algBytes:         []byte(alg),
		sigDecodedLen:    sigDecLen,
		sigEncodedLen:    sigEncLen,
		encodedHeaderDot: defaultHdrDot,
		secret:           append([]byte(nil), secret...),
		edPub:            append(ed25519.PublicKey(nil), edPub...),
		edPriv:           append(ed25519.PrivateKey(nil), opts.Ed25519PrivateKey...),
		ecPub:            ecPub,
		ecPriv:           opts.ECDSAPrivateKey,
		keys:             cKeys,
		leewaySec:        int64(opts.Leeway / time.Second),
		maxHeaderSize:    hdrSize,
		maxPayloadSize:   plSize,
		zeroMemory:       opts.ZeroMemory,
		requireExp:       opts.RequireExp,
	}
	if opts.ExpectedIssuer != "" {
		v.expectedIss = []byte(opts.ExpectedIssuer)
	}
	if opts.ExpectedAudience != "" {
		v.expectedAud = []byte(opts.ExpectedAudience)
	}
	v.pool.New = func() any {
		return v.NewScratch()
	}
	return v, nil
}

// validateConfig rejects configurations that would make verification unsafe or signing meaningless.
func validateConfig(secret []byte, alg Algorithm, opts Options) error {
	invalid := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidConfig, fmt.Sprintf(format, a...))
	}
	minHS := 0
	switch alg {
	case AlgHS256:
		minHS = 32
	case AlgHS384:
		minHS = 48
	case AlgHS512:
		minHS = 64
	case AlgEdDSA, AlgES256:
	default:
		return invalid("unsupported algorithm %q", string(alg))
	}
	isHS := minHS > 0

	seen := make(map[string]struct{}, len(opts.Keys))
	for i, k := range opts.Keys {
		if k.ID == "" {
			return invalid("Keys[%d]: empty ID", i)
		}
		if _, dup := seen[k.ID]; dup {
			return invalid("Keys[%d]: duplicate ID %q", i, k.ID)
		}
		seen[k.ID] = struct{}{}
		switch {
		case isHS:
			if len(k.Secret) == 0 {
				return invalid("Keys[%d] (%q): %s needs a non-empty Secret", i, k.ID, alg)
			}
			if opts.StrictSecretLength && len(k.Secret) < minHS {
				return invalid("Keys[%d] (%q): %s secret must be at least %d bytes", i, k.ID, alg, minHS)
			}
		case alg == AlgEdDSA:
			if len(k.Ed25519Public) != ed25519.PublicKeySize {
				return invalid("Keys[%d] (%q): EdDSA needs a %d-byte Ed25519Public", i, k.ID, ed25519.PublicKeySize)
			}
		case alg == AlgES256:
			if k.ECDSAPublic == nil || k.ECDSAPublic.Curve != elliptic.P256() {
				return invalid("Keys[%d] (%q): ES256 needs a P-256 ECDSAPublic", i, k.ID)
			}
		}
	}

	switch {
	case isHS:
		if len(secret) == 0 {
			if len(opts.Keys) == 0 {
				return invalid("empty HMAC secret")
			}
		} else if opts.StrictSecretLength && len(secret) < minHS {
			return invalid("%s secret must be at least %d bytes (RFC 7518 §3.2)", alg, minHS)
		}
	case alg == AlgEdDSA:
		pub, priv := opts.Ed25519PublicKey, opts.Ed25519PrivateKey
		if len(pub) == 0 {
			if len(priv) == 0 && len(opts.Keys) == 0 {
				return invalid("missing Ed25519 key")
			}
		} else if len(pub) != ed25519.PublicKeySize {
			return invalid("Ed25519 public key must be %d bytes", ed25519.PublicKeySize)
		}
		if len(priv) != 0 && len(priv) != ed25519.PrivateKeySize {
			return invalid("Ed25519 private key must be %d bytes", ed25519.PrivateKeySize)
		}
	case alg == AlgES256:
		pub, priv := opts.ECDSAPublicKey, opts.ECDSAPrivateKey
		if pub == nil {
			if priv == nil && len(opts.Keys) == 0 {
				return invalid("missing ECDSA key")
			}
		} else if pub.Curve != elliptic.P256() {
			return invalid("ES256 requires a P-256 public key")
		}
		if priv != nil {
			if priv.Curve != elliptic.P256() {
				return invalid("ES256 requires a P-256 private key")
			}
			if priv.D == nil || priv.D.Sign() <= 0 || priv.D.Cmp(priv.Params().N) >= 0 {
				return invalid("ES256 requires a valid P-256 private key scalar (1 <= D < N)")
			}
		}
	}
	if opts.Leeway > 0 && opts.Leeway < time.Second {
		return invalid("Leeway must be at least 1s (got %v)", opts.Leeway)
	}
	return nil
}

// Destroy makes the Verifier unusable and wipes, on a best-effort basis, the key material it owns:
// the HMAC secret, its private copy of the Ed25519 private key and the secrets of registered Keys.
// Afterwards Verify* returns ErrVerifierDestroyed and Sign* returns nil.
//
// This is memory hygiene, not a compliance guarantee. Not scrubbed: the slices you passed in,
// HMAC state cached inside pooled Scratch values (the standard library's hmac keeps key-derived
// pads) and an *ecdsa.PrivateKey you share with the Verifier (only the reference is dropped).
// Destroy must not be called concurrently with other methods.
func (v *Verifier) Destroy() {
	v.destroyed.Store(true)
	memclr(v.secret)
	memclr(v.edPriv)
	for i := range v.keys {
		memclr(v.keys[i].secret)
	}
	v.ecPriv = nil
}

// CanSign reports whether this Verifier holds the key material needed to issue tokens.
// Verify-only nodes (for example EdDSA or ES256 without a private key) return false, and
// Sign* methods return nil on them instead of producing a token with an invalid signature.
func (v *Verifier) CanSign() bool {
	if v.destroyed.Load() {
		return false
	}
	switch v.alg {
	case AlgEdDSA:
		return len(v.edPriv) == ed25519.PrivateKeySize
	case AlgES256:
		return v.ecPriv != nil
	default:
		return len(v.secret) > 0
	}
}

func (v *Verifier) newHasher(sec []byte) hash.Hash {
	switch v.alg {
	case AlgHS384:
		return hmac.New(sha512.New384, sec)
	case AlgHS512:
		return hmac.New(sha512.New, sec)
	case AlgHS256:
		return hmac.New(sha256.New, sec)
	default:
		return nil
	}
}

// NewScratch allocates a new Scratch state bound to this Verifier's keys and buffer sizes.
// Useful for single-threaded event-loop servers (e.g. gnet) using VerifyWithScratch.
func (v *Verifier) NewScratch() *Scratch {
	st := &Scratch{
		mac: v.newHasher(v.secret),
	}
	if len(v.keys) > 0 && (v.alg == AlgHS256 || v.alg == AlgHS384 || v.alg == AlgHS512) {
		st.keyMacs = make([]hash.Hash, len(v.keys))
		for i, k := range v.keys {
			st.keyMacs[i] = v.newHasher(k.secret)
		}
	}
	if v.maxHeaderSize <= len(st.hdrArr) {
		st.hdrBuf = st.hdrArr[:v.maxHeaderSize]
	} else {
		st.hdrBuf = make([]byte, v.maxHeaderSize)
	}
	if v.maxPayloadSize <= len(st.payloadArr) {
		st.payloadBuf = st.payloadArr[:v.maxPayloadSize]
	} else {
		st.payloadBuf = make([]byte, v.maxPayloadSize)
	}
	return st
}

func (v *Verifier) releaseScratch(st *Scratch) {
	if v.zeroMemory {
		st.Clear()
	}
	v.pool.Put(st)
}

// VerifyBearer strips the "Bearer " prefix from an HTTP Authorization header
// and verifies the token with zero heap allocations.
func (v *Verifier) VerifyBearer(authHeader []byte, nowUnix int64, out *Claims) error {
	if !bytes.HasPrefix(authHeader, bearerPrefix) {
		return ErrMissingBearer
	}
	return v.Verify(authHeader[len(bearerPrefix):], nowUnix, out)
}

// Verify validates the token signature, checks temporal ("exp", "nbf") and structural
// ("iss", "aud") claims against nowUnix, and populates out with the parsed claims.
// Safe for concurrent use across goroutines; performs 0 heap allocations (0 B/op, 0 allocs/op).
func (v *Verifier) Verify(tok []byte, nowUnix int64, out *Claims) error {
	st := v.pool.Get().(*Scratch)
	err := v.VerifyWithScratch(tok, nowUnix, out, st)
	v.releaseScratch(st)
	return err
}

// VerifyWithScratch performs the same verification as Verify using a caller-supplied Scratch,
// avoiding sync.Pool.Get/Put in single-threaded event loops (such as gnet with LockOSThread).
func (v *Verifier) VerifyWithScratch(tok []byte, nowUnix int64, out *Claims, st *Scratch) error {
	plBytes, err := v.verifySignatureAndDecodePayload(tok, st)
	if err != nil {
		return err
	}
	return v.parseStandardClaims(plBytes, nowUnix, out)
}

// VerifyLarge validates the token and populates a ClaimsLarge struct (256B buffers per claim).
func (v *Verifier) VerifyLarge(tok []byte, nowUnix int64, out *ClaimsLarge) error {
	st := v.pool.Get().(*Scratch)
	err := v.VerifyLargeWithScratch(tok, nowUnix, out, st)
	v.releaseScratch(st)
	return err
}

// VerifyLargeWithScratch validates the token into ClaimsLarge using a caller-supplied Scratch.
func (v *Verifier) VerifyLargeWithScratch(tok []byte, nowUnix int64, out *ClaimsLarge, st *Scratch) error {
	plBytes, err := v.verifySignatureAndDecodePayload(tok, st)
	if err != nil {
		return err
	}
	return v.parseLargeClaims(plBytes, nowUnix, out)
}

// VerifyCustom validates the token signature, checks "exp", "nbf", "iss", and "aud" against nowUnix,
// and invokes onClaim(key, val, isString) for every top-level JSON claim in the payload.
// Performs 0 heap allocations. Note: key and val slices are valid only during the onClaim callback.
func (v *Verifier) VerifyCustom(tok []byte, nowUnix int64, onClaim func(key, val []byte, isStr bool) bool) error {
	st := v.pool.Get().(*Scratch)
	plBytes, err := v.verifySignatureAndDecodePayload(tok, st)
	if err != nil {
		v.releaseScratch(st)
		return err
	}

	body, ok := TrimJSONObject(plBytes)
	if !ok {
		v.releaseScratch(st)
		return ErrInvalidPayload
	}

	expCutoff := float64(nowUnix - v.leewaySec)
	nbfCutoff := float64(nowUnix + v.leewaySec)
	matchedIss := len(v.expectedIss) == 0
	matchedAud := len(v.expectedAud) == 0
	sawExp := false
	sawNbf := false

	for len(body) > 0 {
		key, val, isStr, rest, ok := NextJSONProp(body)
		if !ok {
			v.releaseScratch(st)
			return ErrInvalidPayload
		}
		body = bytes.TrimSpace(rest)

		if len(key) == 3 {
			if key[0] == 'e' && key[1] == 'x' && key[2] == 'p' {
				if sawExp || isStr {
					v.releaseScratch(st)
					return ErrInvalidPayload
				}
				expSec, ok := ParseNumeric(val)
				if !ok {
					v.releaseScratch(st)
					return ErrInvalidPayload
				}
				sawExp = true
				if expCutoff >= expSec {
					v.releaseScratch(st)
					return ErrExpiredToken
				}
			} else if key[0] == 'n' && key[1] == 'b' && key[2] == 'f' {
				if sawNbf || isStr {
					v.releaseScratch(st)
					return ErrInvalidPayload
				}
				nbfSec, ok := ParseNumeric(val)
				if !ok {
					v.releaseScratch(st)
					return ErrInvalidPayload
				}
				sawNbf = true
				if nbfCutoff < nbfSec {
					v.releaseScratch(st)
					return ErrNotValidYet
				}
			} else if key[0] == 'i' && key[1] == 's' && key[2] == 's' && len(v.expectedIss) > 0 {
				if bytes.IndexByte(val, '\\') >= 0 {
					val = UnescapeJSONInPlace(val)
				}
				if !isStr || !bytes.Equal(val, v.expectedIss) {
					v.releaseScratch(st)
					return ErrInvalidIssuer
				}
				matchedIss = true
			} else if key[0] == 'a' && key[1] == 'u' && key[2] == 'd' && len(v.expectedAud) > 0 {
				if !matchAudienceClaim(val, isStr, v.expectedAud, nil) {
					v.releaseScratch(st)
					return ErrInvalidAudience
				}
				matchedAud = true
			}
		}

		if onClaim != nil && !onClaim(key, val, isStr) {
			v.releaseScratch(st)
			return ErrInvalidPayload
		}
	}

	if v.requireExp && !sawExp {
		v.releaseScratch(st)
		return ErrMissingExp
	}
	if !matchedIss {
		v.releaseScratch(st)
		return ErrInvalidIssuer
	}
	if !matchedAud {
		v.releaseScratch(st)
		return ErrInvalidAudience
	}

	v.releaseScratch(st)
	return nil
}

// TrySign signs a raw JSON payload with the Verifier's configured algorithm
// (HS256, HS384, HS512, EdDSA, ES256) and appends the complete JWT token
// ("header.payload.signature") to dst with zero heap allocations (when dst has sufficient capacity).
//
// If signing fails, it returns nil and a typed error (ErrVerifierDestroyed, ErrNoSigningKey,
// ErrPayloadTooLarge, or ErrSigningFailed), leaving dst unmodified.
func (v *Verifier) TrySign(dst []byte, payloadJSON []byte) ([]byte, error) {
	st := v.pool.Get().(*Scratch)
	res, err := v.TrySignWithScratch(dst, payloadJSON, st)
	v.releaseScratch(st)
	return res, err
}

// TrySignWithScratch is identical to TrySign but uses a caller-supplied Scratch state.
func (v *Verifier) TrySignWithScratch(dst []byte, payloadJSON []byte, st *Scratch) ([]byte, error) {
	if v.destroyed.Load() {
		return nil, ErrVerifierDestroyed
	}
	if !v.CanSign() {
		return nil, ErrNoSigningKey
	}
	if len(payloadJSON) > v.maxPayloadSize {
		return nil, ErrPayloadTooLarge
	}
	enc := base64.RawURLEncoding
	start := len(dst)
	pEncLen := enc.EncodedLen(len(payloadJSON))
	hdrLen := len(v.encodedHeaderDot)
	totalLen := hdrLen + pEncLen + 1 + v.sigEncodedLen

	// Ensure capacity in dst
	if cap(dst)-start < totalLen {
		grown := make([]byte, start, start+totalLen)
		copy(grown, dst)
		dst = grown
	}

	// 1. Append pre-encoded Base64URL header + '.'
	dst = append(dst, v.encodedHeaderDot...)

	// 2. Encode payload directly into dst
	pStart := len(dst)
	dst = dst[:pStart+pEncLen]
	enc.Encode(dst[pStart:], payloadJSON)

	// 3. Compute signature over "header.payload"
	signingInput := dst[start:]
	var sig []byte
	switch v.alg {
	case AlgEdDSA:
		edSig := ed25519.Sign(v.edPriv, signingInput)
		copy(st.sumBuf[:64], edSig)
		sig = st.sumBuf[:64]
	case AlgES256:
		digest := sha256.Sum256(signingInput)
		asn1Sig, err := ecdsa.SignASN1(rand.Reader, v.ecPriv, digest[:])
		if err != nil || !decodeDERToP1363(asn1Sig, st.sumBuf[:64]) {
			return nil, ErrSigningFailed
		}
		sig = st.sumBuf[:64]
	default:
		st.mac.Reset()
		_, _ = st.mac.Write(signingInput)
		sig = st.mac.Sum(st.sumBuf[:0])
	}

	// 4. Append '.' and Base64URL-encoded signature
	dst = append(dst, '.')
	sigStart := len(dst)
	dst = dst[:sigStart+v.sigEncodedLen]
	enc.Encode(dst[sigStart:], sig)

	return dst, nil
}

// Sign signs a raw JSON payload with the Verifier's configured algorithm
// (HS256, HS384, HS512, EdDSA, ES256) and appends the complete JWT token
// ("header.payload.signature") to dst with zero heap allocations (when dst has sufficient capacity).
//
// Sign reports failure by returning nil: see TrySign for typed errors.
func (v *Verifier) Sign(dst []byte, payloadJSON []byte) []byte {
	tok, _ := v.TrySign(dst, payloadJSON)
	return tok
}

// SignWithScratch signs a raw JSON payload using a caller-supplied Scratch state.
// It reports failure by returning nil: see TrySignWithScratch for typed errors.
func (v *Verifier) SignWithScratch(dst []byte, payloadJSON []byte, st *Scratch) []byte {
	tok, _ := v.TrySignWithScratch(dst, payloadJSON, st)
	return tok
}

// SignHS256 signs a raw JSON payload and appends the complete JWT token
// ("header.payload.signature") to dst with zero heap allocations (when dst has sufficient capacity).
// It reports failure by returning nil: see TrySign for typed errors.
func (v *Verifier) SignHS256(dst []byte, payloadJSON []byte) []byte {
	return v.Sign(dst, payloadJSON)
}

// SignHS256WithScratch signs a raw JSON payload using a caller-supplied Scratch state.
// It reports failure by returning nil: see TrySignWithScratch for typed errors.
func (v *Verifier) SignHS256WithScratch(dst []byte, payloadJSON []byte, st *Scratch) []byte {
	return v.SignWithScratch(dst, payloadJSON, st)
}

// TrySignClaims formats a standard JSON payload `{"sub":"...","username":"...","iat":...,"exp":...}`
// into Scratch and appends the signed JWT token to dst with zero heap allocations.
//
// It returns a typed error if the Verifier cannot sign, if RequireExp is set and exp <= 0,
// if sub is empty or exceeds 256 bytes (ClaimsLarge capacity limit), if username exceeds
// 256 bytes, or if the resulting payload exceeds MaxPayloadSize.
// (Note: standard Claims struct supports sub <= 64 bytes and username <= 128 bytes via Verify;
// callers verifying into standard Claims should remain within those bounds or use VerifyLarge).
func (v *Verifier) TrySignClaims(dst []byte, sub, username []byte, iat, exp int64) ([]byte, error) {
	st := v.pool.Get().(*Scratch)
	res, err := v.TrySignClaimsWithScratch(dst, sub, username, iat, exp, st)
	v.releaseScratch(st)
	return res, err
}

// TrySignClaimsWithScratch is identical to TrySignClaims but uses caller-supplied Scratch state.
func (v *Verifier) TrySignClaimsWithScratch(dst []byte, sub, username []byte, iat, exp int64, st *Scratch) ([]byte, error) {
	if v.destroyed.Load() {
		return nil, ErrVerifierDestroyed
	}
	if !v.CanSign() {
		return nil, ErrNoSigningKey
	}
	if v.requireExp && exp <= 0 {
		return nil, ErrMissingExp
	}
	if len(sub) == 0 || len(sub) > 256 {
		return nil, ErrInvalidPayload
	}
	if len(username) > 256 {
		return nil, ErrInvalidPayload
	}
	b := st.payloadBuf[:0]
	b = append(b, `{"sub":`...)
	b = AppendEscapedJSONString(b, sub)
	if len(username) > 0 {
		b = append(b, `,"username":`...)
		b = AppendEscapedJSONString(b, username)
	}
	if len(v.expectedIss) > 0 {
		b = append(b, `,"iss":`...)
		b = AppendEscapedJSONString(b, v.expectedIss)
	}
	if len(v.expectedAud) > 0 {
		b = append(b, `,"aud":`...)
		b = AppendEscapedJSONString(b, v.expectedAud)
	}
	if iat > 0 {
		b = append(b, `,"iat":`...)
		b = strconv.AppendInt(b, iat, 10)
	}
	if exp > 0 {
		b = append(b, `,"exp":`...)
		b = strconv.AppendInt(b, exp, 10)
	}
	b = append(b, '}')

	return v.TrySignWithScratch(dst, b, st)
}

// SignClaims formats a standard JSON payload `{"sub":"...","username":"...","iat":...,"exp":...}`
// into Scratch and appends the signed JWT token to dst with zero heap allocations.
//
// It returns nil on any failure condition (see TrySignClaims for typed errors).
func (v *Verifier) SignClaims(dst []byte, sub, username []byte, iat, exp int64) []byte {
	tok, _ := v.TrySignClaims(dst, sub, username, iat, exp)
	return tok
}

func (v *Verifier) verifySignatureAndDecodePayload(tok []byte, st *Scratch) ([]byte, error) {
	if v.destroyed.Load() {
		return nil, ErrVerifierDestroyed
	}
	// Go's base64 decoder silently skips CR/LF; reject them so a token has a single accepted form.
	if bytes.IndexByte(tok, '\n') >= 0 || bytes.IndexByte(tok, '\r') >= 0 {
		return nil, ErrInvalidToken
	}
	// 1. Split header.payload.signature using bytes.Cut (0 allocations)
	hBytes, rest, hasDot1 := bytes.Cut(tok, dotByte)
	if !hasDot1 || len(hBytes) == 0 {
		return nil, ErrInvalidToken
	}
	pBytes, sBytes, hasDot2 := bytes.Cut(rest, dotByte)
	if !hasDot2 || len(pBytes) == 0 || len(sBytes) == 0 || bytes.IndexByte(sBytes, '.') >= 0 {
		return nil, ErrInvalidToken
	}

	enc := rawURLStrict

	// 2. Decode header into scratch buffer and verify "alg", optional "typ", and optional "kid"
	if enc.DecodedLen(len(hBytes)) > len(st.hdrBuf) {
		return nil, ErrInvalidHeader
	}
	nHdr, err := enc.Decode(st.hdrBuf, hBytes)
	if err != nil || nHdr == 0 {
		return nil, ErrInvalidHeader
	}
	keyIdx, err := v.validateHeader(st.hdrBuf[:nHdr])
	if err != nil {
		return nil, err
	}

	// 3. Decode signature
	if enc.DecodedLen(len(sBytes)) > len(st.sigBuf) {
		return nil, ErrInvalidSignature
	}
	nSig, err := enc.Decode(st.sigBuf[:], sBytes)
	if err != nil || nSig != v.sigDecodedLen {
		return nil, ErrInvalidSignature
	}

	// 4. Verify signature
	signingInputLen := len(hBytes) + 1 + len(pBytes)
	switch v.alg {
	case AlgEdDSA:
		pub := v.edPub
		if keyIdx >= 0 {
			pub = v.keys[keyIdx].ed25519Public
		}
		if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, tok[:signingInputLen], st.sigBuf[:64]) {
			return nil, ErrInvalidSignature
		}
	case AlgES256:
		pub := v.ecPub
		if keyIdx >= 0 {
			pub = v.keys[keyIdx].ecdsaPublic
		}
		if pub == nil {
			return nil, ErrInvalidSignature
		}
		derSig, ok := encodeP1363ToDER(&st.derBuf, st.sigBuf[:32], st.sigBuf[32:64])
		if !ok {
			return nil, ErrInvalidSignature
		}
		digest := sha256.Sum256(tok[:signingInputLen])
		if !ecdsa.VerifyASN1(pub, digest[:], derSig) {
			return nil, ErrInvalidSignature
		}
	default:
		mac := st.mac
		if keyIdx >= 0 {
			if len(v.keys[keyIdx].secret) == 0 {
				return nil, ErrInvalidSignature
			}
			mac = st.keyMacs[keyIdx]
		} else if len(v.secret) == 0 {
			return nil, ErrInvalidSignature
		}
		mac.Reset()
		_, _ = mac.Write(tok[:signingInputLen])
		calculated := mac.Sum(st.sumBuf[:0])
		if !hmac.Equal(st.sigBuf[:v.sigDecodedLen], calculated) {
			return nil, ErrInvalidSignature
		}
	}

	// 5. Decode payload into scratch buffer
	if enc.DecodedLen(len(pBytes)) > len(st.payloadBuf) {
		return nil, ErrPayloadTooLarge
	}
	nPl, err := enc.Decode(st.payloadBuf, pBytes)
	if err != nil || nPl == 0 {
		return nil, ErrInvalidPayload
	}

	return st.payloadBuf[:nPl], nil
}

func (v *Verifier) validateHeader(h []byte) (int, error) {
	body, ok := TrimJSONObject(h)
	if !ok {
		return -1, ErrInvalidHeader
	}
	hasAlg := false
	hasTyp := false
	hasKid := false
	keyIdx := -1
	first := true
	for len(body) > 0 {
		if first {
			if body[0] != '"' {
				return -1, ErrInvalidHeader
			}
			first = false
		} else {
			if body[0] != ',' {
				return -1, ErrInvalidHeader
			}
			afterComma := bytes.TrimSpace(body[1:])
			if len(afterComma) == 0 || afterComma[0] != '"' {
				return -1, ErrInvalidHeader
			}
			body = afterComma
		}
		key, val, isStr, rest, ok := NextJSONProp(body)
		if !ok {
			return -1, ErrInvalidHeader
		}
		body = bytes.TrimSpace(rest)
		if bytes.Equal(key, algKey) {
			if hasAlg || !isStr || !bytes.Equal(val, v.algBytes) {
				return -1, ErrInvalidHeader
			}
			hasAlg = true
		} else if bytes.Equal(key, typKey) {
			if hasTyp || !isStr || !bytes.EqualFold(val, jwtVal) {
				return -1, ErrInvalidHeader
			}
			hasTyp = true
		} else if bytes.Equal(key, critKey) {
			// RFC 7515 §4.1.11: unknown critical extensions MUST be rejected; none are supported.
			return -1, ErrInvalidHeader
		} else if bytes.Equal(key, kidKey) {
			if hasKid || !isStr || len(val) == 0 {
				return -1, ErrInvalidHeader
			}
			hasKid = true
			if bytes.IndexByte(val, '\\') >= 0 {
				val = UnescapeJSONInPlace(val)
			}
			if len(v.keys) > 0 {
				found := -1
				for i := range v.keys {
					if bytes.Equal(v.keys[i].idBytes, val) {
						found = i
						break
					}
				}
				if found < 0 {
					return -1, ErrUnknownKeyID
				}
				keyIdx = found
			}
		}
	}
	if !hasAlg {
		return -1, ErrInvalidHeader
	}
	return keyIdx, nil
}

func (v *Verifier) parseStandardClaims(b []byte, now int64, out *Claims) error {
	if v.zeroMemory {
		out.Clear()
	} else {
		out.Reset()
	}

	body, ok := TrimJSONObject(b)
	if !ok {
		return ErrInvalidPayload
	}

	expCutoff := float64(now - v.leewaySec)
	nbfCutoff := float64(now + v.leewaySec)

	for len(body) > 0 {
		key, val, isStr, rest, ok := NextJSONProp(body)
		if !ok {
			return ErrInvalidPayload
		}
		body = bytes.TrimSpace(rest)

		switch string(key) {
		case "exp":
			if out.HasExp || isStr {
				return ErrInvalidPayload
			}
			expSec, ok := ParseNumeric(val)
			if !ok {
				return ErrInvalidPayload
			}
			out.ExpiresAt = int64(expSec)
			out.HasExp = true
			if expCutoff >= expSec {
				return ErrExpiredToken
			}
		case "nbf":
			if out.HasNbf || isStr {
				return ErrInvalidPayload
			}
			nbfSec, ok := ParseNumeric(val)
			if !ok {
				return ErrInvalidPayload
			}
			out.NotBefore = int64(nbfSec)
			out.HasNbf = true
			if nbfCutoff < nbfSec {
				return ErrNotValidYet
			}
		case "iat":
			if out.HasIat || isStr {
				return ErrInvalidPayload
			}
			iatSec, ok := ParseNumeric(val)
			if !ok {
				return ErrInvalidPayload
			}
			out.IssuedAt = int64(iatSec)
			out.HasIat = true
		case "sub":
			if out.HasSub || !isStr || len(val) == 0 {
				return ErrInvalidPayload
			}
			if bytes.IndexByte(val, '\\') >= 0 {
				val = UnescapeJSONInPlace(val)
			}
			if len(val) == 0 || len(val) > len(out.subBuf) {
				return ErrInvalidPayload
			}
			copy(out.subBuf[:], val)
			out.subLen = uint8(len(val))
			out.HasSub = true
			if id, ok := ParsePositiveInt(val); ok {
				out.SubjectID = id
			}
		case "username":
			if out.HasUsername || !isStr {
				return ErrInvalidPayload
			}
			if bytes.IndexByte(val, '\\') >= 0 {
				val = UnescapeJSONInPlace(val)
			}
			if len(val) > len(out.userBuf) {
				return ErrInvalidPayload
			}
			copy(out.userBuf[:], val)
			out.userLen = uint8(len(val))
			out.HasUsername = true
		case "iss":
			if out.HasIss || !isStr {
				return ErrInvalidPayload
			}
			if bytes.IndexByte(val, '\\') >= 0 {
				val = UnescapeJSONInPlace(val)
			}
			if len(val) > len(out.issBuf) {
				return ErrInvalidPayload
			}
			if len(v.expectedIss) > 0 && !bytes.Equal(val, v.expectedIss) {
				return ErrInvalidIssuer
			}
			copy(out.issBuf[:], val)
			out.issLen = uint8(len(val))
			out.HasIss = true
		case "aud":
			if out.HasAud {
				return ErrInvalidPayload
			}
			var captured []byte
			if !matchAudienceClaim(val, isStr, v.expectedAud, &captured) {
				if isStr && len(v.expectedAud) > 0 {
					return ErrInvalidAudience
				}
				if !isStr && len(val) > 0 && val[0] == '[' && len(v.expectedAud) > 0 {
					return ErrInvalidAudience
				}
				return ErrInvalidPayload
			}
			if len(captured) > len(out.audBuf) {
				return ErrInvalidPayload
			}
			copy(out.audBuf[:], captured)
			out.audLen = uint8(len(captured))
			out.HasAud = true
		case "jti":
			if out.HasJti || !isStr {
				return ErrInvalidPayload
			}
			if bytes.IndexByte(val, '\\') >= 0 {
				val = UnescapeJSONInPlace(val)
			}
			if len(val) > len(out.jtiBuf) {
				return ErrInvalidPayload
			}
			copy(out.jtiBuf[:], val)
			out.jtiLen = uint8(len(val))
			out.HasJti = true
		}
	}

	if len(v.expectedIss) > 0 && !out.HasIss {
		return ErrInvalidIssuer
	}
	if len(v.expectedAud) > 0 && !out.HasAud {
		return ErrInvalidAudience
	}
	if v.requireExp && !out.HasExp {
		return ErrMissingExp
	}
	if !out.HasSub {
		return ErrInvalidPayload
	}
	return nil
}

func (v *Verifier) parseLargeClaims(b []byte, now int64, out *ClaimsLarge) error {
	if v.zeroMemory {
		out.Clear()
	} else {
		out.Reset()
	}

	body, ok := TrimJSONObject(b)
	if !ok {
		return ErrInvalidPayload
	}

	expCutoff := float64(now - v.leewaySec)
	nbfCutoff := float64(now + v.leewaySec)

	for len(body) > 0 {
		key, val, isStr, rest, ok := NextJSONProp(body)
		if !ok {
			return ErrInvalidPayload
		}
		body = bytes.TrimSpace(rest)

		switch string(key) {
		case "exp":
			if out.HasExp || isStr {
				return ErrInvalidPayload
			}
			expSec, ok := ParseNumeric(val)
			if !ok {
				return ErrInvalidPayload
			}
			out.ExpiresAt = int64(expSec)
			out.HasExp = true
			if expCutoff >= expSec {
				return ErrExpiredToken
			}
		case "nbf":
			if out.HasNbf || isStr {
				return ErrInvalidPayload
			}
			nbfSec, ok := ParseNumeric(val)
			if !ok {
				return ErrInvalidPayload
			}
			out.NotBefore = int64(nbfSec)
			out.HasNbf = true
			if nbfCutoff < nbfSec {
				return ErrNotValidYet
			}
		case "iat":
			if out.HasIat || isStr {
				return ErrInvalidPayload
			}
			iatSec, ok := ParseNumeric(val)
			if !ok {
				return ErrInvalidPayload
			}
			out.IssuedAt = int64(iatSec)
			out.HasIat = true
		case "sub":
			if out.HasSub || !isStr || len(val) == 0 {
				return ErrInvalidPayload
			}
			if bytes.IndexByte(val, '\\') >= 0 {
				val = UnescapeJSONInPlace(val)
			}
			if len(val) == 0 || len(val) > len(out.subBuf) {
				return ErrInvalidPayload
			}
			copy(out.subBuf[:], val)
			out.subLen = uint16(len(val))
			out.HasSub = true
			if id, ok := ParsePositiveInt(val); ok {
				out.SubjectID = id
			}
		case "username":
			if out.HasUsername || !isStr {
				return ErrInvalidPayload
			}
			if bytes.IndexByte(val, '\\') >= 0 {
				val = UnescapeJSONInPlace(val)
			}
			if len(val) > len(out.userBuf) {
				return ErrInvalidPayload
			}
			copy(out.userBuf[:], val)
			out.userLen = uint16(len(val))
			out.HasUsername = true
		case "iss":
			if out.HasIss || !isStr {
				return ErrInvalidPayload
			}
			if bytes.IndexByte(val, '\\') >= 0 {
				val = UnescapeJSONInPlace(val)
			}
			if len(val) > len(out.issBuf) {
				return ErrInvalidPayload
			}
			if len(v.expectedIss) > 0 && !bytes.Equal(val, v.expectedIss) {
				return ErrInvalidIssuer
			}
			copy(out.issBuf[:], val)
			out.issLen = uint16(len(val))
			out.HasIss = true
		case "aud":
			if out.HasAud {
				return ErrInvalidPayload
			}
			var captured []byte
			if !matchAudienceClaim(val, isStr, v.expectedAud, &captured) {
				if isStr && len(v.expectedAud) > 0 {
					return ErrInvalidAudience
				}
				if !isStr && len(val) > 0 && val[0] == '[' && len(v.expectedAud) > 0 {
					return ErrInvalidAudience
				}
				return ErrInvalidPayload
			}
			if len(captured) > len(out.audBuf) {
				return ErrInvalidPayload
			}
			copy(out.audBuf[:], captured)
			out.audLen = uint16(len(captured))
			out.HasAud = true
		case "jti":
			if out.HasJti || !isStr {
				return ErrInvalidPayload
			}
			if bytes.IndexByte(val, '\\') >= 0 {
				val = UnescapeJSONInPlace(val)
			}
			if len(val) > len(out.jtiBuf) {
				return ErrInvalidPayload
			}
			copy(out.jtiBuf[:], val)
			out.jtiLen = uint16(len(val))
			out.HasJti = true
		}
	}

	if len(v.expectedIss) > 0 && !out.HasIss {
		return ErrInvalidIssuer
	}
	if len(v.expectedAud) > 0 && !out.HasAud {
		return ErrInvalidAudience
	}
	if v.requireExp && !out.HasExp {
		return ErrMissingExp
	}
	if !out.HasSub {
		return ErrInvalidPayload
	}
	return nil
}

// matchAudienceClaim validates an "aud" value (which RFC 7519 allows to be either a single JSON string
// or a JSON array of strings) against expectedAud with zero heap allocations.
func matchAudienceClaim(val []byte, isStr bool, expectedAud []byte, capturedOut *[]byte) bool {
	if isStr {
		if bytes.IndexByte(val, '\\') >= 0 {
			val = UnescapeJSONInPlace(val)
		}
		if capturedOut != nil {
			*capturedOut = val
		}
		if len(expectedAud) > 0 && !bytes.Equal(val, expectedAud) {
			return false
		}
		return true
	}
	arrBody, ok := TrimJSONArray(val)
	if !ok || len(arrBody) == 0 {
		return false
	}
	matched := len(expectedAud) == 0
	first := true
	for len(arrBody) > 0 {
		elem, elemIsStr, rest, ok := NextArrayElement(arrBody)
		if !ok || !elemIsStr {
			return false
		}
		arrBody = rest
		if bytes.IndexByte(elem, '\\') >= 0 {
			elem = UnescapeJSONInPlace(elem)
		}
		if first {
			if capturedOut != nil {
				*capturedOut = elem
			}
			first = false
		}
		if len(expectedAud) > 0 && bytes.Equal(elem, expectedAud) {
			matched = true
			if capturedOut != nil {
				*capturedOut = elem
			}
		}
	}
	return matched
}

// encodeP1363ToDER converts a 64-byte IEEE P1363 ECDSA signature (r || s) into ASN.1 DER inside dst.
func encodeP1363ToDER(dst *[72]byte, r, s []byte) ([]byte, bool) {
	for len(r) > 0 && r[0] == 0 {
		r = r[1:]
	}
	for len(s) > 0 && s[0] == 0 {
		s = s[1:]
	}
	if len(r) == 0 || len(s) == 0 {
		return nil, false
	}
	rPad := 0
	if r[0]&0x80 != 0 {
		rPad = 1
	}
	sPad := 0
	if s[0]&0x80 != 0 {
		sPad = 1
	}
	rLen := len(r) + rPad
	sLen := len(s) + sPad
	seqLen := 2 + rLen + 2 + sLen

	dst[0] = 0x30
	dst[1] = byte(seqLen)
	dst[2] = 0x02
	dst[3] = byte(rLen)
	idx := 4
	if rPad == 1 {
		dst[idx] = 0x00
		idx++
	}
	idx += copy(dst[idx:], r)
	dst[idx] = 0x02
	dst[idx+1] = byte(sLen)
	idx += 2
	if sPad == 1 {
		dst[idx] = 0x00
		idx++
	}
	idx += copy(dst[idx:], s)
	return dst[:idx], true
}

// decodeDERToP1363 extracts 32-byte r and s integers from an ASN.1 DER ECDSA signature into dst (64 bytes).
func decodeDERToP1363(der, dst []byte) bool {
	if len(der) < 8 || der[0] != 0x30 {
		return false
	}
	idx := 2
	if der[1]&0x80 != 0 {
		idx++
	}
	if idx >= len(der) || der[idx] != 0x02 {
		return false
	}
	rLen := int(der[idx+1])
	idx += 2
	if idx+rLen > len(der) {
		return false
	}
	rBytes := der[idx : idx+rLen]
	idx += rLen
	if idx+2 > len(der) || der[idx] != 0x02 {
		return false
	}
	sLen := int(der[idx+1])
	idx += 2
	if idx+sLen != len(der) {
		return false
	}
	sBytes := der[idx : idx+sLen]

	for len(rBytes) > 0 && rBytes[0] == 0 {
		rBytes = rBytes[1:]
	}
	for len(sBytes) > 0 && sBytes[0] == 0 {
		sBytes = sBytes[1:]
	}
	if len(rBytes) > 32 || len(sBytes) > 32 {
		return false
	}
	memclr(dst[:64])
	copy(dst[32-len(rBytes):32], rBytes)
	copy(dst[64-len(sBytes):64], sBytes)
	return true
}
