package zerojwt

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"math/big"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// Algorithm identifies a supported JWS cryptographic algorithm.
type Algorithm string

const (
	// AlgHS256 represents HMAC using SHA-256 (RFC 7518 §3.2).
	AlgHS256 Algorithm = "HS256"
	// AlgHS384 represents HMAC using SHA-384 (RFC 7518 §3.2).
	AlgHS384 Algorithm = "HS384"
	// AlgHS512 represents HMAC using SHA-512 (RFC 7518 §3.2).
	AlgHS512 Algorithm = "HS512"
	// AlgEdDSA represents Ed25519 signature algorithm (RFC 8037 §3.1).
	AlgEdDSA Algorithm = "EdDSA"
	// AlgES256 represents ECDSA using P-256 and SHA-256 (RFC 7518 §3.4).
	AlgES256 Algorithm = "ES256"
	// AlgES384 represents ECDSA using P-384 and SHA-384 (RFC 7518 §3.4).
	AlgES384 Algorithm = "ES384"
	// AlgES512 represents ECDSA using P-521 and SHA-512 (RFC 7518 §3.4).
	AlgES512 Algorithm = "ES512"
	// AlgRS256 represents RSASSA-PKCS1-v1_5 using SHA-256 (RFC 7518 §3.3).
	AlgRS256 Algorithm = "RS256"
)

// String returns the algorithm name string.
func (a Algorithm) String() string {
	return string(a)
}

const (
	// MaxHeaderSize defines the default maximum decoded byte length of a JWT header.
	MaxHeaderSize = 128
	// MaxPayloadSize defines the default maximum decoded byte length of a JWT payload.
	MaxPayloadSize = 1024

	// MaxZeroAllocSplitSigningInput defines the maximum byte length of stitched signing input
	// (Base64URL(Header) + '.' + Base64URL(Payload)) accommodated by Scratch.signArr (1544 bytes)
	// for zero-allocation split verification of asymmetric algorithms (EdDSA, ECDSA, RSA).
	// Default MaxHeaderSize (128) and MaxPayloadSize (1024) require at most 1538 bytes, guaranteeing
	// 0 allocs/op. For HMAC algorithms, split verification streams bytes into the hasher and is always 0 allocs/op.
	MaxZeroAllocSplitSigningInput = 1544

	// MaxZeroAllocSplitPayloadSize defines the default maximum decoded payload byte size (1024)
	// that guarantees 0 allocs/op during asymmetric VerifySplit.
	MaxZeroAllocSplitPayloadSize = MaxPayloadSize

	// Maximum standard claim field buffer lengths
	MaxSubjectSize  = 256 // OIDC Core 1.0 §2 requires sub <= 255 ASCII characters
	MaxUsernameSize = 128
	MaxIssuerSize   = 256
	MaxAudienceSize = 256
	MaxJTISize      = 64
)

const (
	encodedHS256HeaderDot = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
	encodedHS384HeaderDot = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9."
	encodedHS512HeaderDot = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9."
	encodedEdDSAHeaderDot = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9."
	encodedES256HeaderDot = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9."
	encodedES384HeaderDot = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9."
	encodedES512HeaderDot = "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9."
	encodedRS256HeaderDot = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
)

var (
	algKey       = []byte("alg")
	typKey       = []byte("typ")
	kidKey       = []byte("kid")
	critKey      = []byte("crit")
	jwtVal       = []byte("JWT")
	dotByte      = []byte(".")
	bearerPrefix = []byte("Bearer ")
	rawURLStrict = base64.RawURLEncoding.Strict()
)

// Key defines a named cryptographic key for automatic "kid" header lookup.
type Key struct {
	ID            string
	Secret        []byte
	Ed25519Public ed25519.PublicKey
	ECDSAPublic   *ecdsa.PublicKey
	RSAPublic     *rsa.PublicKey
}

type compiledKey struct {
	idBytes       []byte
	secret        []byte
	ed25519Public ed25519.PublicKey
	ecdsaPublic   *ecdsa.PublicKey
	rsaPublic     *rsa.PublicKey
}

type keySet struct {
	keys       []compiledKey
	keyVersion int64
}

// Options configures algorithm, buffer sizes, clock skew leeway, issuer/audience rules,
// key rotation ("kid"), and opt-in relaxations for secure-by-default behavior.
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
	// ExpectedAudience enforces that the token's "aud" claim contains this value.
	ExpectedAudience string
	// Keys registers named keys for automatic "kid" header lookup during verification.
	Keys []Key
	// ActiveKeyID embeds `"kid":"<ActiveKeyID>"` in the JWT header when signing tokens.
	ActiveKeyID string
	// Ed25519PublicKey is the 32-byte public key used when Algorithm is AlgEdDSA.
	Ed25519PublicKey ed25519.PublicKey
	// Ed25519PrivateKey is the 64-byte private key used for signing when Algorithm is AlgEdDSA.
	Ed25519PrivateKey ed25519.PrivateKey
	// ECDSAPublicKey is the ECDSA public key used when Algorithm is AlgES256, AlgES384, or AlgES512.
	ECDSAPublicKey *ecdsa.PublicKey
	// ECDSAPrivateKey is the ECDSA private key used for signing when Algorithm is AlgES256, AlgES384, or AlgES512.
	ECDSAPrivateKey *ecdsa.PrivateKey
	// RSAPublicKey is the RSA public key used when Algorithm is AlgRS256.
	RSAPublicKey *rsa.PublicKey
	// RSAPrivateKey is the RSA private key used for signing when Algorithm is AlgRS256.
	RSAPrivateKey *rsa.PrivateKey
	// ZeroMemory zeroes out internal scratch buffers with 0x00 after each operation.
	ZeroMemory bool
	// AllowMissingExp relaxes the default requirement that tokens must contain an "exp" claim.
	// In v2, RequireExp is true by default; setting AllowMissingExp: true opts out.
	AllowMissingExp bool
	// AllowShortSecret relaxes the default RFC 7518 §3.2 minimum HMAC key size
	// (32B for HS256, 48B for HS384, 64B for HS512). In v2, StrictSecretLength is true by default.
	AllowShortSecret bool
}

// Scratch holds reusable buffers and pre-initialized HMAC/SHA-256 hashers.
type Scratch struct {
	mac        hash.Hash
	keyMacs    []hash.Hash
	keyVersion int64
	sigBuf     [512]byte
	sumBuf     [64]byte
	derBuf     [144]byte
	hdrBuf     []byte
	payloadBuf []byte
	hdrArr     [MaxHeaderSize]byte
	payloadArr [MaxPayloadSize]byte
	signArr    [1544]byte // holds Base64URL(MaxHeaderSize) + '.' + Base64URL(MaxPayloadSize) (171+1+1366 = 1538, 8B-aligned)
}

func memclr(b []byte) {
	clear(b)
}

// Clear zeroes out all internal working buffers in Scratch using runtime memclr.
func (s *Scratch) Clear() {
	memclr(s.sigBuf[:])
	memclr(s.sumBuf[:])
	memclr(s.derBuf[:])
	memclr(s.hdrBuf)
	memclr(s.payloadBuf)
	memclr(s.signArr[:])
}

// Claims holds standard JWT claims on the caller's stack without heap allocations.
// In v2, Claims unifies standard and large claims into a single 1016-byte struct
// with 8-byte CPU word alignment, supporting subjects up to 255 ASCII characters
// per OIDC Core 1.0 §2 directly in-line.
type Claims struct {
	SubjectID   int64     // Parsed positive integer ID when "sub" is numeric
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
	subLen      uint16    // Length of Subject in subBuf
	userLen     uint16    // Length of Username in userBuf
	issLen      uint16    // Length of Issuer in issBuf
	audLen      uint16    // Length of Audience in audBuf
	jtiLen      uint16    // Length of JTI in jtiBuf
	_           [6]byte   // explicit 6-byte padding to align to 8-byte boundary (56 bytes header)
	subBuf      [256]byte // OIDC Core 1.0 §2 compliant (<= 255 ASCII characters)
	userBuf     [128]byte
	issBuf      [256]byte
	audBuf      [256]byte
	jtiBuf      [64]byte
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

// Reset resets length markers and flags for fast reuse without zeroing underlying byte arrays.
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

// ClaimsLarge is a compatibility alias for Claims in v2.
type ClaimsLarge = Claims

// StandardClaims defines standard registered claims for emitting tokens with SignClaims.
type StandardClaims struct {
	Subject   string
	Username  string
	Issuer    string
	Audience  string
	JTI       string
	IssuedAt  int64
	ExpiresAt int64
	NotBefore int64
}

// Verifier validates and signs JWT tokens with zero heap allocations (0 B/op, 0 allocs/op).
// A Verifier is 100% safe for concurrent use by multiple goroutines.
type Verifier struct {
	alg                   Algorithm
	algBytes              []byte
	sigDecodedLen         int
	sigEncodedLen         int
	encodedHeaderDot      string
	encodedHeaderDotBytes []byte
	secret                []byte
	edPub                 ed25519.PublicKey
	edPriv                ed25519.PrivateKey
	ecPub                 *ecdsa.PublicKey
	ecPriv                *ecdsa.PrivateKey
	rsaPub                *rsa.PublicKey
	rsaPriv               *rsa.PrivateKey
	keys                  []compiledKey
	keySetPtr             atomic.Pointer[keySet]
	keyVersionSeq         atomic.Int64
	strictSecret          bool
	leewaySec             int64
	expectedIss           []byte
	expectedAud           []byte
	maxHeaderSize         int
	maxPayloadSize        int
	zeroMemory            bool
	requireExp            bool
	destroyed             atomic.Bool
	pool                  sync.Pool
	randReader            io.Reader
}

// New creates a new concurrent-safe Verifier with strict, secure-by-default production settings
// (RFC 7518 §3.2 minimum HMAC secret length, OIDC Core 1.0 §3.1.3.7 / RFC 9068 §2.2 mandatory "exp" claim).
//
// To opt out of expiration enforcement or minimum key lengths, configure Options with
// AllowMissingExp: true and/or AllowShortSecret: true.
func New(secret []byte, opts ...Options) (*Verifier, error) {
	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}
	if opt.Algorithm == "" {
		opt.Algorithm = AlgHS256
	}
	return newVerifier(secret, opt)
}

// NewWithOptions is an alias for New(secret, opts).
func NewWithOptions(secret []byte, opts Options) (*Verifier, error) {
	return New(secret, opts)
}

// Deprecated: Use New instead. NewSecureVerifier is a convenience alias for New in v2.
func NewSecureVerifier(secret []byte, opts ...Options) (*Verifier, error) {
	return New(secret, opts...)
}

// NewEd25519Verifier creates a new concurrent-safe EdDSA (Ed25519) Verifier.
// It cross-validates that pub and priv form a mathematically matching key pair.
// For verification-only nodes, priv can be nil.
func NewEd25519Verifier(pub ed25519.PublicKey, priv ed25519.PrivateKey, opts ...Options) (*Verifier, error) {
	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}
	opt.Algorithm = AlgEdDSA
	opt.Ed25519PublicKey = pub
	opt.Ed25519PrivateKey = priv
	return New(nil, opt)
}

// NewES256Verifier creates a new concurrent-safe ECDSA P-256 (ES256) Verifier.
// It cross-validates that pub and priv form a mathematically matching key pair and that
// the private key scalar satisfies 1 <= D < N.
// For verification-only nodes, priv can be nil.
func NewES256Verifier(pub *ecdsa.PublicKey, priv *ecdsa.PrivateKey, opts ...Options) (*Verifier, error) {
	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}
	opt.Algorithm = AlgES256
	opt.ECDSAPublicKey = pub
	opt.ECDSAPrivateKey = priv
	return New(nil, opt)
}

// NewES384Verifier creates a new concurrent-safe ECDSA P-384 (ES384) Verifier.
// It cross-validates that pub and priv form a mathematically matching key pair and that
// the private key scalar satisfies 1 <= D < N.
// For verification-only nodes, priv can be nil.
func NewES384Verifier(pub *ecdsa.PublicKey, priv *ecdsa.PrivateKey, opts ...Options) (*Verifier, error) {
	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}
	opt.Algorithm = AlgES384
	opt.ECDSAPublicKey = pub
	opt.ECDSAPrivateKey = priv
	return New(nil, opt)
}

// NewES512Verifier creates a new concurrent-safe ECDSA P-521 (ES512) Verifier.
// It cross-validates that pub and priv form a mathematically matching key pair and that
// the private key scalar satisfies 1 <= D < N.
// For verification-only nodes, priv can be nil.
func NewES512Verifier(pub *ecdsa.PublicKey, priv *ecdsa.PrivateKey, opts ...Options) (*Verifier, error) {
	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}
	opt.Algorithm = AlgES512
	opt.ECDSAPublicKey = pub
	opt.ECDSAPrivateKey = priv
	return New(nil, opt)
}

// NewRS256Verifier creates a new concurrent-safe RSASSA-PKCS1-v1_5 (RS256) Verifier.
// It cross-validates that pub and priv form a mathematically matching key pair,
// that N is 2048-4096 bits and odd, that E is odd and in [65537, 2^31-1], and validates the private key.
// For verification-only nodes, priv can be nil.
func NewRS256Verifier(pub *rsa.PublicKey, priv *rsa.PrivateKey, opts ...Options) (*Verifier, error) {
	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}
	opt.Algorithm = AlgRS256
	opt.RSAPublicKey = pub
	opt.RSAPrivateKey = priv
	return New(nil, opt)
}

func newVerifier(secret []byte, opts Options) (*Verifier, error) {
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
	case AlgES384:
		sigDecLen = 96
		sigEncLen = 128
		defaultHdrDot = encodedES384HeaderDot
	case AlgES512:
		sigDecLen = 132
		sigEncLen = 176
		defaultHdrDot = encodedES512HeaderDot
	case AlgRS256:
		sigDecLen = 256
		if opts.RSAPublicKey != nil {
			sigDecLen = opts.RSAPublicKey.Size()
		} else if opts.RSAPrivateKey != nil {
			sigDecLen = opts.RSAPrivateKey.Size()
		}
		sigEncLen = base64.RawURLEncoding.EncodedLen(sigDecLen)
		defaultHdrDot = encodedRS256HeaderDot
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
		hdrJSON = AppendEscapedJSON(hdrJSON, opts.ActiveKeyID)
		hdrJSON = append(hdrJSON, '}')
		defaultHdrDot = base64.RawURLEncoding.EncodeToString(hdrJSON) + "."
	}

	cKeys := compileKeys(opts.Keys)

	edPub := opts.Ed25519PublicKey
	if len(edPub) == 0 && len(opts.Ed25519PrivateKey) == ed25519.PrivateKeySize {
		edPub = opts.Ed25519PrivateKey.Public().(ed25519.PublicKey)
	}
	ecPub := opts.ECDSAPublicKey
	if ecPub == nil && opts.ECDSAPrivateKey != nil {
		ecPub = cloneECDSAPublicKey(&opts.ECDSAPrivateKey.PublicKey)
	}
	rsaPub := opts.RSAPublicKey
	if rsaPub == nil && opts.RSAPrivateKey != nil {
		rsaPub = cloneRSAPublicKey(&opts.RSAPrivateKey.PublicKey)
	}

	v := &Verifier{
		alg:                   alg,
		algBytes:              []byte(alg),
		sigDecodedLen:         sigDecLen,
		sigEncodedLen:         sigEncLen,
		encodedHeaderDot:      defaultHdrDot,
		encodedHeaderDotBytes: []byte(defaultHdrDot),
		secret:                append([]byte(nil), secret...),
		edPub:                 append(ed25519.PublicKey(nil), edPub...),
		edPriv:                append(ed25519.PrivateKey(nil), opts.Ed25519PrivateKey...),
		ecPub:                 cloneECDSAPublicKey(ecPub),
		ecPriv:                opts.ECDSAPrivateKey,
		rsaPub:                cloneRSAPublicKey(rsaPub),
		rsaPriv:               opts.RSAPrivateKey,
		keys:                  cKeys,
		strictSecret:          !opts.AllowShortSecret,
		leewaySec:             int64(opts.Leeway / time.Second),
		maxHeaderSize:         hdrSize,
		maxPayloadSize:        plSize,
		zeroMemory:            opts.ZeroMemory,
		requireExp:            !opts.AllowMissingExp, // secure by default in v2
	}
	ks := &keySet{
		keys:       cKeys,
		keyVersion: 1,
	}
	v.keySetPtr.Store(ks)
	v.keyVersionSeq.Store(1)

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
	case AlgEdDSA, AlgES256, AlgES384, AlgES512, AlgRS256:
	default:
		return invalid("unsupported algorithm %q", string(alg))
	}
	isHS := minHS > 0
	strictSecret := !opts.AllowShortSecret // secure by default in v2

	if err := validateKeysList(opts.Keys, alg, strictSecret); err != nil {
		return err
	}

	switch {
	case isHS:
		if len(secret) == 0 {
			if len(opts.Keys) == 0 {
				return invalid("empty HMAC secret")
			}
		} else if strictSecret && len(secret) < minHS {
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
		if len(priv) != 0 {
			if len(priv) != ed25519.PrivateKeySize {
				return invalid("Ed25519 private key must be %d bytes", ed25519.PrivateKeySize)
			}
			if len(pub) == ed25519.PublicKeySize {
				derivedPub, ok := priv.Public().(ed25519.PublicKey)
				if !ok || !bytes.Equal(derivedPub, pub) {
					return ErrMismatchedKeyPair
				}
			}
		}
	case alg == AlgES256:
		pub, priv := opts.ECDSAPublicKey, opts.ECDSAPrivateKey
		if pub == nil {
			if priv == nil && len(opts.Keys) == 0 {
				return invalid("missing ECDSA key")
			}
		} else if !isValidP256PublicKey(pub) {
			return invalid("ES256 requires a valid P-256 public key")
		}
		if priv != nil {
			if !isValidP256PublicKey(&priv.PublicKey) {
				return invalid("ES256 requires a valid P-256 private key")
			}
			if priv.D == nil || priv.D.Sign() <= 0 || priv.D.Cmp(priv.Params().N) >= 0 {
				return invalid("ES256 requires a valid P-256 private key scalar (1 <= D < N)")
			}
			if pub != nil && !priv.PublicKey.Equal(pub) {
				return ErrMismatchedKeyPair
			}
		}
	case alg == AlgES384:
		pub, priv := opts.ECDSAPublicKey, opts.ECDSAPrivateKey
		if pub == nil {
			if priv == nil && len(opts.Keys) == 0 {
				return invalid("missing ECDSA key")
			}
		} else if !isValidP384PublicKey(pub) {
			return invalid("ES384 requires a valid P-384 public key")
		}
		if priv != nil {
			if !isValidP384PublicKey(&priv.PublicKey) {
				return invalid("ES384 requires a valid P-384 private key")
			}
			if priv.D == nil || priv.D.Sign() <= 0 || priv.D.Cmp(priv.Params().N) >= 0 {
				return invalid("ES384 requires a valid P-384 private key scalar (1 <= D < N)")
			}
			if pub != nil && !priv.PublicKey.Equal(pub) {
				return ErrMismatchedKeyPair
			}
		}
	case alg == AlgES512:
		pub, priv := opts.ECDSAPublicKey, opts.ECDSAPrivateKey
		if pub == nil {
			if priv == nil && len(opts.Keys) == 0 {
				return invalid("missing ECDSA key")
			}
		} else if !isValidP521PublicKey(pub) {
			return invalid("ES512 requires a valid P-521 public key")
		}
		if priv != nil {
			if !isValidP521PublicKey(&priv.PublicKey) {
				return invalid("ES512 requires a valid P-521 private key")
			}
			if priv.D == nil || priv.D.Sign() <= 0 || priv.D.Cmp(priv.Params().N) >= 0 {
				return invalid("ES512 requires a valid P-521 private key scalar (1 <= D < N)")
			}
			if pub != nil && !priv.PublicKey.Equal(pub) {
				return ErrMismatchedKeyPair
			}
		}
	case alg == AlgRS256:
		pub, priv := opts.RSAPublicKey, opts.RSAPrivateKey
		if pub == nil {
			if priv == nil && len(opts.Keys) == 0 {
				return invalid("missing RSA key")
			}
		} else if !isValidRSAPublicKey(pub) {
			return invalid("RS256 requires a valid RSA public key (2048-4096 bits, odd modulus, odd E >= 65537)")
		}
		if priv != nil {
			if err := priv.Validate(); err != nil {
				return invalid("RS256 invalid private key: %v", err)
			}
			if !isValidRSAPublicKey(&priv.PublicKey) {
				return invalid("RS256 requires a valid RSA private key (2048-4096 bits)")
			}
			if pub != nil && (priv.PublicKey.N.Cmp(pub.N) != 0 || priv.PublicKey.E != pub.E) {
				return ErrMismatchedKeyPair
			}
		}
	}
	if opts.Leeway > 0 && opts.Leeway < time.Second {
		return invalid("Leeway must be at least 1s (got %v)", opts.Leeway)
	}
	return nil
}

func isValidP256PublicKey(pub *ecdsa.PublicKey) bool {
	return pub != nil &&
		pub.Curve == elliptic.P256() &&
		pub.X != nil && pub.Y != nil &&
		pub.X.Sign() > 0 && pub.Y.Sign() > 0 &&
		pub.Curve.IsOnCurve(pub.X, pub.Y)
}

func isValidP384PublicKey(pub *ecdsa.PublicKey) bool {
	return pub != nil &&
		pub.Curve == elliptic.P384() &&
		pub.X != nil && pub.Y != nil &&
		pub.X.Sign() > 0 && pub.Y.Sign() > 0 &&
		pub.Curve.IsOnCurve(pub.X, pub.Y)
}

func isValidP521PublicKey(pub *ecdsa.PublicKey) bool {
	return pub != nil &&
		pub.Curve == elliptic.P521() &&
		pub.X != nil && pub.Y != nil &&
		pub.X.Sign() > 0 && pub.Y.Sign() > 0 &&
		pub.Curve.IsOnCurve(pub.X, pub.Y)
}

func isValidRSAPublicKey(pub *rsa.PublicKey) bool {
	if pub == nil || pub.N == nil {
		return false
	}
	bitLen := pub.N.BitLen()
	if bitLen < 2048 || bitLen > 4096 || pub.N.Bit(0) == 0 {
		return false
	}
	if pub.E < 65537 || pub.E > 2147483647 || pub.E%2 == 0 {
		return false
	}
	return true
}

func cloneECDSAPublicKey(pub *ecdsa.PublicKey) *ecdsa.PublicKey {
	if pub == nil {
		return nil
	}
	return &ecdsa.PublicKey{
		Curve: pub.Curve,
		X:     new(big.Int).Set(pub.X),
		Y:     new(big.Int).Set(pub.Y),
	}
}

func cloneRSAPublicKey(pub *rsa.PublicKey) *rsa.PublicKey {
	if pub == nil {
		return nil
	}
	var n *big.Int
	if pub.N != nil {
		n = new(big.Int).Set(pub.N)
	}
	return &rsa.PublicKey{
		N: n,
		E: pub.E,
	}
}

func compileKeys(keys []Key) []compiledKey {
	if len(keys) == 0 {
		return nil
	}
	cKeys := make([]compiledKey, len(keys))
	for i, k := range keys {
		cKeys[i] = compiledKey{
			idBytes:       []byte(k.ID),
			secret:        append([]byte(nil), k.Secret...),
			ed25519Public: append(ed25519.PublicKey(nil), k.Ed25519Public...),
			ecdsaPublic:   cloneECDSAPublicKey(k.ECDSAPublic),
			rsaPublic:     cloneRSAPublicKey(k.RSAPublic),
		}
	}
	return cKeys
}

func validateKeysList(keys []Key, alg Algorithm, strictSecret bool) error {
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
	case AlgEdDSA, AlgES256, AlgES384, AlgES512, AlgRS256:
	default:
		return invalid("unsupported algorithm %q", string(alg))
	}
	isHS := minHS > 0

	seen := make(map[string]struct{}, len(keys))
	for i, k := range keys {
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
			if strictSecret && len(k.Secret) < minHS {
				return invalid("Keys[%d] (%q): %s secret must be at least %d bytes", i, k.ID, alg, minHS)
			}
		case alg == AlgEdDSA:
			if len(k.Ed25519Public) != ed25519.PublicKeySize {
				return invalid("Keys[%d] (%q): EdDSA needs a %d-byte Ed25519Public", i, k.ID, ed25519.PublicKeySize)
			}
		case alg == AlgES256:
			if !isValidP256PublicKey(k.ECDSAPublic) {
				return invalid("Keys[%d] (%q): ES256 needs a valid P-256 ECDSAPublic", i, k.ID)
			}
		case alg == AlgES384:
			if !isValidP384PublicKey(k.ECDSAPublic) {
				return invalid("Keys[%d] (%q): ES384 needs a valid P-384 ECDSAPublic", i, k.ID)
			}
		case alg == AlgES512:
			if !isValidP521PublicKey(k.ECDSAPublic) {
				return invalid("Keys[%d] (%q): ES512 needs a valid P-521 ECDSAPublic", i, k.ID)
			}
		case alg == AlgRS256:
			if !isValidRSAPublicKey(k.RSAPublic) {
				return invalid("Keys[%d] (%q): RS256 needs a valid RSA public key (2048-4096 bits)", i, k.ID)
			}
		}
	}
	return nil
}

// getKeySet returns the current active keySet pointer atomically with zero locks.
func (v *Verifier) getKeySet() *keySet {
	if ks := v.keySetPtr.Load(); ks != nil {
		return ks
	}
	return &keySet{keys: v.keys, keyVersion: 1}
}

// UpdateKeys atomically replaces the registered "kid" key set in the Verifier without downtime.
// It is 100% thread-safe and lock-free for concurrent verification during live traffic.
func (v *Verifier) UpdateKeys(keys []Key) error {
	if v.destroyed.Load() {
		return ErrVerifierDestroyed
	}
	if err := validateKeysList(keys, v.alg, v.strictSecret); err != nil {
		return err
	}
	cKeys := compileKeys(keys)
	newVer := v.keyVersionSeq.Add(1)
	newKS := &keySet{
		keys:       cKeys,
		keyVersion: newVer,
	}
	if v.zeroMemory {
		runtime.SetFinalizer(newKS, finalizeKeySet)
	}
	v.keySetPtr.Store(newKS)
	return nil
}

func finalizeKeySet(ks *keySet) {
	for i := range ks.keys {
		memclr(ks.keys[i].secret)
	}
}

// CanSign reports whether this Verifier holds key material needed to issue tokens.
func (v *Verifier) CanSign() bool {
	if v.destroyed.Load() {
		return false
	}
	switch v.alg {
	case AlgEdDSA:
		return len(v.edPriv) == ed25519.PrivateKeySize
	case AlgES256, AlgES384, AlgES512:
		return v.ecPriv != nil
	case AlgRS256:
		return v.rsaPriv != nil
	default:
		return len(v.secret) > 0
	}
}

// Algorithm returns the configured JWS algorithm.
func (v *Verifier) Algorithm() Algorithm { return v.alg }

// MaxHeaderSize returns the configured maximum decoded header size in bytes.
func (v *Verifier) MaxHeaderSize() int { return v.maxHeaderSize }

// MaxPayloadSize returns the configured maximum decoded payload size in bytes.
func (v *Verifier) MaxPayloadSize() int { return v.maxPayloadSize }

// Destroy marks the Verifier as destroyed and zeroes out sensitive private key material.
func (v *Verifier) Destroy() {
	if v.destroyed.Swap(true) {
		return
	}
	memclr(v.secret)
	memclr(v.edPriv)
	for i := range v.keys {
		memclr(v.keys[i].secret)
	}
	if ks := v.keySetPtr.Load(); ks != nil {
		for i := range ks.keys {
			memclr(ks.keys[i].secret)
		}
	}
	v.ecPriv = nil
	v.rsaPriv = nil
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

func (st *Scratch) getOrInitKeyMac(keyIdx int, ks *keySet, newHasher func([]byte) hash.Hash) hash.Hash {
	if st.keyVersion == ks.keyVersion && keyIdx < len(st.keyMacs) {
		return st.keyMacs[keyIdx]
	}
	return st.getOrInitKeyMacSlow(keyIdx, ks, newHasher)
}

//go:noinline
func (st *Scratch) getOrInitKeyMacSlow(keyIdx int, ks *keySet, newHasher func([]byte) hash.Hash) hash.Hash {
	st.keyVersion = ks.keyVersion
	newMacs := make([]hash.Hash, len(ks.keys))
	for i := range ks.keys {
		newMacs[i] = newHasher(ks.keys[i].secret)
	}
	st.keyMacs = newMacs
	return newMacs[keyIdx]
}

// NewScratch allocates a new Scratch state bound to this Verifier's keys and buffer sizes.
func (v *Verifier) NewScratch() *Scratch {
	ks := v.getKeySet()
	st := &Scratch{
		mac:        v.newHasher(v.secret),
		keyVersion: ks.keyVersion,
	}
	if len(ks.keys) > 0 && (v.alg == AlgHS256 || v.alg == AlgHS384 || v.alg == AlgHS512) {
		st.keyMacs = make([]hash.Hash, len(ks.keys))
		for i, k := range ks.keys {
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

func (v *Verifier) acquireScratch() *Scratch {
	val := v.pool.Get()
	if val == nil {
		return v.NewScratch()
	}
	return val.(*Scratch)
}

func (v *Verifier) releaseScratch(st *Scratch) {
	if v.zeroMemory {
		st.Clear()
	}
	v.pool.Put(st)
}

// Sign signs a raw JSON payload with the Verifier's configured algorithm
// and appends the complete JWT token ("header.payload.signature") to dst.
//
// In v2, Sign follows the idiomatic Go append contract: on error, it rolls back
// dst to its original length, preserving caller capacity without side effects.
func (v *Verifier) Sign(dst []byte, payloadJSON []byte) ([]byte, error) {
	st := v.acquireScratch()
	res, err := v.SignWithScratch(dst, payloadJSON, st)
	v.releaseScratch(st)
	return res, err
}

// SignWithScratch is identical to Sign but uses a caller-supplied Scratch state.
func (v *Verifier) SignWithScratch(dst []byte, payloadJSON []byte, st *Scratch) ([]byte, error) {
	start := len(dst)
	if v.destroyed.Load() {
		return dst[:start], ErrVerifierDestroyed
	}
	if !v.CanSign() {
		return dst[:start], ErrNoSigningKey
	}
	if len(payloadJSON) > v.maxPayloadSize {
		return dst[:start], ErrPayloadTooLarge
	}
	enc := base64.RawURLEncoding
	pEncLen := enc.EncodedLen(len(payloadJSON))
	hdrLen := len(v.encodedHeaderDot)
	sigEncLen := v.sigEncodedLen
	if v.alg == AlgRS256 && v.rsaPriv != nil {
		sigEncLen = enc.EncodedLen(v.rsaPriv.Size())
	}
	totalLen := hdrLen + pEncLen + 1 + sigEncLen

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
		rr := v.randReader
		if rr == nil {
			rr = rand.Reader
		}
		asn1Sig, err := ecdsa.SignASN1(rr, v.ecPriv, digest[:])
		if err != nil || !decodeDERToP1363(asn1Sig, st.sigBuf[:64]) {
			return dst[:start], ErrSigningFailed
		}
		sig = st.sigBuf[:64]
	case AlgES384:
		digest := sha512.Sum384(signingInput)
		rr := v.randReader
		if rr == nil {
			rr = rand.Reader
		}
		asn1Sig, err := ecdsa.SignASN1(rr, v.ecPriv, digest[:])
		if err != nil || !decodeDERToP1363(asn1Sig, st.sigBuf[:96]) {
			return dst[:start], ErrSigningFailed
		}
		sig = st.sigBuf[:96]
	case AlgES512:
		digest := sha512.Sum512(signingInput)
		rr := v.randReader
		if rr == nil {
			rr = rand.Reader
		}
		asn1Sig, err := ecdsa.SignASN1(rr, v.ecPriv, digest[:])
		if err != nil || !decodeDERToP1363(asn1Sig, st.sigBuf[:132]) {
			return dst[:start], ErrSigningFailed
		}
		sig = st.sigBuf[:132]
	case AlgRS256:
		digest := sha256.Sum256(signingInput)
		rr := v.randReader
		if rr == nil {
			rr = rand.Reader
		}
		rsaSig, err := rsa.SignPKCS1v15(rr, v.rsaPriv, crypto.SHA256, digest[:])
		if err != nil {
			return dst[:start], ErrSigningFailed
		}
		sig = rsaSig
	default:
		st.mac.Reset()
		_, _ = st.mac.Write(signingInput)
		sig = st.mac.Sum(st.sumBuf[:0])
	}

	// 4. Append '.' and Base64URL-encoded signature
	dst = append(dst, '.')
	sigStart := len(dst)
	dst = dst[:sigStart+sigEncLen]
	enc.Encode(dst[sigStart:], sig)

	return dst, nil
}

// SignClaims formats standard registered claims into Scratch and appends
// the signed JWT token to dst with zero heap allocations.
//
// In v2, SignClaims enforces:
// - Subject length <= 256 bytes (OIDC Core 1.0 §2 requires <= 255 ASCII characters)
// - Username length <= 128 bytes
// - Issuer length <= 256 bytes
// - Audience length <= 256 bytes
// - JTI length <= 64 bytes
// - When RequireExp is active (default), claims.ExpiresAt must be > 0.
//
// If signing fails, dst is rolled back to its original length.
func (v *Verifier) SignClaims(dst []byte, claims StandardClaims) ([]byte, error) {
	st := v.acquireScratch()
	res, err := v.SignClaimsWithScratch(dst, claims, st)
	v.releaseScratch(st)
	return res, err
}

// SignClaimsWithScratch is identical to SignClaims but uses a caller-supplied Scratch state.
func (v *Verifier) SignClaimsWithScratch(dst []byte, claims StandardClaims, st *Scratch) ([]byte, error) {
	start := len(dst)
	if v.destroyed.Load() {
		return dst[:start], ErrVerifierDestroyed
	}
	if !v.CanSign() {
		return dst[:start], ErrNoSigningKey
	}
	if v.requireExp && claims.ExpiresAt <= 0 {
		return dst[:start], ErrMissingExp
	}
	if len(claims.Subject) == 0 || len(claims.Subject) > MaxSubjectSize {
		return dst[:start], ErrInvalidPayload
	}
	if len(claims.Username) > MaxUsernameSize {
		return dst[:start], ErrInvalidPayload
	}
	if len(claims.Issuer) > MaxIssuerSize {
		return dst[:start], ErrInvalidPayload
	}
	if len(claims.Audience) > MaxAudienceSize {
		return dst[:start], ErrInvalidPayload
	}
	if len(claims.JTI) > MaxJTISize {
		return dst[:start], ErrInvalidPayload
	}

	iss := claims.Issuer
	if len(iss) == 0 && len(v.expectedIss) > 0 {
		iss = string(v.expectedIss)
	}
	aud := claims.Audience
	if len(aud) == 0 && len(v.expectedAud) > 0 {
		aud = string(v.expectedAud)
	}

	b := st.payloadBuf[:0]
	b = append(b, `{"sub":`...)
	b = AppendEscapedJSON(b, claims.Subject)
	if len(claims.Username) > 0 {
		b = append(b, `,"username":`...)
		b = AppendEscapedJSON(b, claims.Username)
	}
	if len(iss) > 0 {
		b = append(b, `,"iss":`...)
		b = AppendEscapedJSON(b, iss)
	}
	if len(aud) > 0 {
		b = append(b, `,"aud":`...)
		b = AppendEscapedJSON(b, aud)
	}
	if len(claims.JTI) > 0 {
		b = append(b, `,"jti":`...)
		b = AppendEscapedJSON(b, claims.JTI)
	}
	if claims.IssuedAt > 0 {
		b = append(b, `,"iat":`...)
		b = strconv.AppendInt(b, claims.IssuedAt, 10)
	}
	if claims.NotBefore > 0 {
		b = append(b, `,"nbf":`...)
		b = strconv.AppendInt(b, claims.NotBefore, 10)
	}
	if claims.ExpiresAt > 0 {
		b = append(b, `,"exp":`...)
		b = strconv.AppendInt(b, claims.ExpiresAt, 10)
	}
	b = append(b, '}')

	return v.SignWithScratch(dst, b, st)
}

// Deprecated: Use Sign instead. TrySign is a compatibility alias for Sign in v2.
func (v *Verifier) TrySign(dst []byte, payloadJSON []byte) ([]byte, error) {
	return v.Sign(dst, payloadJSON)
}

// Deprecated: Use SignClaims instead. TrySignClaims is a compatibility alias for SignClaims in v2.
func (v *Verifier) TrySignClaims(dst []byte, sub, username []byte, iat, exp int64) ([]byte, error) {
	return v.SignClaims(dst, StandardClaims{
		Subject:   string(sub),
		Username:  string(username),
		IssuedAt:  iat,
		ExpiresAt: exp,
	})
}

// Verify validates the token signature, checks temporal ("exp", "nbf") and structural
// ("iss", "aud") claims against nowUnix, and populates out with the parsed claims.
// Safe for concurrent use across goroutines; performs 0 heap allocations (0 B/op, 0 allocs/op).
func (v *Verifier) Verify(tok []byte, nowUnix int64, out *Claims) error {
	st := v.acquireScratch()
	err := v.VerifyWithScratch(tok, nowUnix, out, st)
	v.releaseScratch(st)
	return err
}

// VerifyWithScratch performs verification using a caller-supplied Scratch state.
func (v *Verifier) VerifyWithScratch(tok []byte, nowUnix int64, out *Claims, st *Scratch) error {
	plBytes, err := v.verifySignatureAndDecodePayload(tok, st)
	if err != nil {
		return err
	}
	return v.parseStandardClaims(plBytes, nowUnix, out)
}

// VerifyBearer strips the "Bearer " prefix (case-insensitively per RFC 7235 / RFC 6750)
// from an HTTP Authorization header and verifies the token with zero heap allocations.
func (v *Verifier) VerifyBearer(authHeader []byte, nowUnix int64, out *Claims) error {
	// SWAR case-insensitive check for "Bearer " (0x72616562 = "bear", 0x7265 = "er")
	if len(authHeader) < 7 ||
		(binary.LittleEndian.Uint32(authHeader[:4])|0x20202020) != 0x72616562 ||
		(binary.LittleEndian.Uint16(authHeader[4:6])|0x2020) != 0x7265 ||
		authHeader[6] != ' ' {
		return ErrMissingBearer
	}
	return v.Verify(authHeader[7:], nowUnix, out)
}

// VerifyNow verifies the token using the current system Unix timestamp (time.Now().Unix()).
// Like Verify, it automatically manages internal workspaces via sync.Pool with 0 B/op and 0 allocs/op.
func (v *Verifier) VerifyNow(tok []byte, out *Claims) error {
	return v.Verify(tok, time.Now().Unix(), out)
}

// VerifyBearerNow parses and verifies an "Authorization: Bearer <token>" header using the current system Unix timestamp.
func (v *Verifier) VerifyBearerNow(authHeader []byte, out *Claims) error {
	return v.VerifyBearer(authHeader, time.Now().Unix(), out)
}

// VerifyBearerWithScratch parses and verifies an "Authorization: Bearer <token>" header using a caller-supplied Scratch state.
func (v *Verifier) VerifyBearerWithScratch(authHeader []byte, nowUnix int64, out *Claims, st *Scratch) error {
	// SWAR case-insensitive check for "Bearer " (0x72616562 = "bear", 0x7265 = "er")
	if len(authHeader) < 7 ||
		(binary.LittleEndian.Uint32(authHeader[:4])|0x20202020) != 0x72616562 ||
		(binary.LittleEndian.Uint16(authHeader[4:6])|0x2020) != 0x7265 ||
		authHeader[6] != ' ' {
		return ErrMissingBearer
	}
	return v.VerifyWithScratch(authHeader[7:], nowUnix, out, st)
}

// stringToBytesRO converts an immutable string to a byte slice with zero heap allocation.
// This is memory-safe in Go 1.20+ because:
// 1. The input string is read-only and immutable.
// 2. The zerojwt verifier methods only read from the slice; they never mutate or retain it.
func stringToBytesRO(s string) []byte {
	if len(s) == 0 {
		return nil
	}
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

// VerifyString verifies a JWT token passed as a string with 0 B/op and 0 allocs/op.
// It is 100% thread-safe and safe under Go 1.20+ as the string is treated as strictly read-only.
func (v *Verifier) VerifyString(tok string, nowUnix int64, out *Claims) error {
	return v.Verify(stringToBytesRO(tok), nowUnix, out)
}

// VerifyStringNow verifies a JWT token passed as a string using the current system Unix timestamp.
func (v *Verifier) VerifyStringNow(tok string, out *Claims) error {
	return v.Verify(stringToBytesRO(tok), time.Now().Unix(), out)
}

// VerifyStringWithScratch verifies a JWT token passed as a string using a caller-provided Scratch state.
func (v *Verifier) VerifyStringWithScratch(tok string, nowUnix int64, out *Claims, st *Scratch) error {
	return v.VerifyWithScratch(stringToBytesRO(tok), nowUnix, out, st)
}

// VerifyBearerString parses and verifies an "Authorization: Bearer <token>" string header.
func (v *Verifier) VerifyBearerString(authHeader string, nowUnix int64, out *Claims) error {
	return v.VerifyBearer(stringToBytesRO(authHeader), nowUnix, out)
}

// VerifyBearerStringNow parses and verifies an "Authorization: Bearer <token>" string header using the current timestamp.
func (v *Verifier) VerifyBearerStringNow(authHeader string, out *Claims) error {
	return v.VerifyBearer(stringToBytesRO(authHeader), time.Now().Unix(), out)
}

// VerifyBearerStringWithScratch parses and verifies an "Authorization: Bearer <token>" string header using a caller-supplied Scratch state.
func (v *Verifier) VerifyBearerStringWithScratch(authHeader string, nowUnix int64, out *Claims, st *Scratch) error {
	return v.VerifyBearerWithScratch(stringToBytesRO(authHeader), nowUnix, out, st)
}

// VerifyLarge is a compatibility alias for Verify in v2.
func (v *Verifier) VerifyLarge(tok []byte, nowUnix int64, out *Claims) error {
	return v.Verify(tok, nowUnix, out)
}

// VerifyLargeWithScratch is a compatibility alias for VerifyWithScratch in v2.
func (v *Verifier) VerifyLargeWithScratch(tok []byte, nowUnix int64, out *Claims, st *Scratch) error {
	return v.VerifyWithScratch(tok, nowUnix, out, st)
}

// VerifyAndIterate validates the token cryptographically and structurally with complete atomicity:
// claims are ONLY yielded to fn if the token is 100% valid, unexpired, and authentic.
// If any validation rule fails, fn is never called and the error is returned immediately.
func (v *Verifier) VerifyAndIterate(tok []byte, nowUnix int64, fn func(key, val []byte, isStr bool) bool) error {
	st := v.acquireScratch()
	err := v.VerifyAndIterateWithScratch(tok, nowUnix, fn, st)
	v.releaseScratch(st)
	return err
}

// VerifyAndIterateWithScratch is identical to VerifyAndIterate but uses a caller-supplied Scratch state.
func (v *Verifier) VerifyAndIterateWithScratch(tok []byte, nowUnix int64, fn func(key, val []byte, isStr bool) bool, st *Scratch) error {
	plBytes, err := v.verifySignatureAndDecodePayload(tok, st)
	if err != nil {
		return err
	}

	body, ok := TrimJSONObject(plBytes)
	if !ok {
		return ErrInvalidPayload
	}

	// Pass 1: Atomic cryptographic & claim validation
	if err := v.validatePayloadClaims(body, nowUnix); err != nil {
		return err
	}

	// Pass 2: Token is 100% valid; invoke callback
	for len(body) > 0 {
		key, val, isStr, rest, _ := NextJSONProp(body)
		body = rest
		if fn != nil && !fn(key, val, isStr) {
			break
		}
	}
	return nil
}

// VerifyCustom is a compatibility alias for VerifyAndIterate in v2.
func (v *Verifier) VerifyCustom(tok []byte, nowUnix int64, onClaim func(key, val []byte, isStr bool) bool) error {
	return v.VerifyAndIterate(tok, nowUnix, onClaim)
}

func (v *Verifier) validatePayloadClaims(body []byte, nowUnix int64) error {
	expCutoff := float64(nowUnix - v.leewaySec)
	nbfCutoff := float64(nowUnix + v.leewaySec)
	matchedIss := len(v.expectedIss) == 0
	matchedAud := len(v.expectedAud) == 0
	sawExp := false
	sawNbf := false
	sawIss := false
	sawAud := false

	for len(body) > 0 {
		key, val, isStr, rest, ok := NextJSONProp(body)
		if !ok {
			return ErrInvalidPayload
		}
		body = rest

		switch string(key) {
		case "exp":
			if sawExp || isStr {
				return ErrInvalidPayload
			}
			expSec, ok := ParseNumeric(val)
			if !ok {
				return ErrInvalidPayload
			}
			sawExp = true
			if expCutoff >= expSec {
				return ErrTokenExpired
			}
		case "nbf":
			if sawNbf || isStr {
				return ErrInvalidPayload
			}
			nbfSec, ok := ParseNumeric(val)
			if !ok {
				return ErrInvalidPayload
			}
			sawNbf = true
			if nbfCutoff < nbfSec {
				return ErrTokenNotValidYet
			}
		case "iss":
			if sawIss {
				return ErrInvalidPayload
			}
			sawIss = true
			if len(v.expectedIss) > 0 {
				if !isStr || !equalJSONString(val, v.expectedIss) {
					return ErrInvalidIssuer
				}
				matchedIss = true
			}
		case "aud":
			if sawAud {
				return ErrInvalidPayload
			}
			sawAud = true
			if len(v.expectedAud) > 0 {
				if !matchAudienceClaim(val, isStr, v.expectedAud, nil) {
					return ErrInvalidAudience
				}
				matchedAud = true
			}
		}
	}

	if v.requireExp && !sawExp {
		return ErrMissingExp
	}
	if !matchedIss {
		return ErrInvalidIssuer
	}
	if !matchedAud {
		return ErrInvalidAudience
	}
	return nil
}

func (v *Verifier) verifySignatureAndDecodePayload(tok []byte, st *Scratch) ([]byte, error) {
	if v.destroyed.Load() {
		return nil, ErrVerifierDestroyed
	}
	// Go's base64 decoder silently skips CR/LF; reject them so token has a single canonical representation
	if bytes.IndexByte(tok, '\n') >= 0 || bytes.IndexByte(tok, '\r') >= 0 {
		return nil, ErrInvalidToken
	}

	hBytes, rest, hasDot1 := bytes.Cut(tok, dotByte)
	if !hasDot1 || len(hBytes) == 0 {
		return nil, ErrInvalidToken
	}
	pBytes, sBytes, hasDot2 := bytes.Cut(rest, dotByte)
	if !hasDot2 || len(pBytes) == 0 || len(sBytes) == 0 || bytes.IndexByte(sBytes, '.') >= 0 {
		return nil, ErrInvalidToken
	}

	enc := rawURLStrict

	// 1. Decode header into scratch buffer
	if enc.DecodedLen(len(hBytes)) > len(st.hdrBuf) {
		return nil, ErrHeaderTooLarge
	}
	nHdr, err := enc.Decode(st.hdrBuf, hBytes)
	if err != nil || nHdr == 0 {
		return nil, ErrInvalidHeader
	}
	ks := v.getKeySet()
	keyIdx, err := v.validateHeader(st.hdrBuf[:nHdr], ks)
	if err != nil {
		return nil, err
	}

	// 2. Enforce payload size bound before signature hashing (prevents CPU DoS on oversized tokens)
	if enc.DecodedLen(len(pBytes)) > len(st.payloadBuf) {
		return nil, ErrPayloadTooLarge
	}

	// 3. Decode signature into scratch buffer
	var rsaPub *rsa.PublicKey
	expectedSigLen := v.sigDecodedLen
	if v.alg == AlgRS256 {
		if keyIdx >= 0 {
			rsaPub = ks.keys[keyIdx].rsaPublic
		} else {
			rsaPub = v.rsaPub
		}
		if rsaPub == nil {
			return nil, ErrInvalidSignature
		}
		expectedSigLen = rsaPub.Size()
	}

	if enc.DecodedLen(len(sBytes)) > len(st.sigBuf) {
		return nil, ErrInvalidSignature
	}
	nSig, err := enc.Decode(st.sigBuf[:], sBytes)
	if err != nil || nSig != expectedSigLen {
		return nil, ErrInvalidSignature
	}

	// 4. Verify signature
	signingInputLen := len(hBytes) + 1 + len(pBytes)
	switch v.alg {
	case AlgEdDSA:
		pub := v.edPub
		if keyIdx >= 0 {
			pub = ks.keys[keyIdx].ed25519Public
		}
		if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, tok[:signingInputLen], st.sigBuf[:64]) {
			return nil, ErrInvalidSignature
		}
	case AlgES256:
		pub := v.ecPub
		if keyIdx >= 0 {
			pub = ks.keys[keyIdx].ecdsaPublic
		}
		if pub == nil {
			return nil, ErrInvalidSignature
		}
		derSig, ok := encodeP1363ToDER(&st.derBuf, st.sigBuf[:32], st.sigBuf[32:64], 32)
		if !ok {
			return nil, ErrInvalidSignature
		}
		digest := sha256.Sum256(tok[:signingInputLen])
		if !ecdsa.VerifyASN1(pub, digest[:], derSig) {
			return nil, ErrInvalidSignature
		}
	case AlgES384:
		pub := v.ecPub
		if keyIdx >= 0 {
			pub = ks.keys[keyIdx].ecdsaPublic
		}
		if pub == nil {
			return nil, ErrInvalidSignature
		}
		derSig, ok := encodeP1363ToDER(&st.derBuf, st.sigBuf[:48], st.sigBuf[48:96], 48)
		if !ok {
			return nil, ErrInvalidSignature
		}
		digest := sha512.Sum384(tok[:signingInputLen])
		if !ecdsa.VerifyASN1(pub, digest[:], derSig) {
			return nil, ErrInvalidSignature
		}
	case AlgES512:
		pub := v.ecPub
		if keyIdx >= 0 {
			pub = ks.keys[keyIdx].ecdsaPublic
		}
		if pub == nil {
			return nil, ErrInvalidSignature
		}
		derSig, ok := encodeP1363ToDER(&st.derBuf, st.sigBuf[:66], st.sigBuf[66:132], 66)
		if !ok {
			return nil, ErrInvalidSignature
		}
		digest := sha512.Sum512(tok[:signingInputLen])
		if !ecdsa.VerifyASN1(pub, digest[:], derSig) {
			return nil, ErrInvalidSignature
		}
	case AlgRS256:
		digest := sha256.Sum256(tok[:signingInputLen])
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], st.sigBuf[:nSig]); err != nil {
			return nil, ErrInvalidSignature
		}
	default:
		mac := st.mac
		if keyIdx >= 0 {
			if len(ks.keys[keyIdx].secret) == 0 {
				return nil, ErrInvalidSignature
			}
			mac = st.getOrInitKeyMac(keyIdx, ks, v.newHasher)
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
	nPl, err := enc.Decode(st.payloadBuf, pBytes)
	if err != nil || nPl == 0 {
		return nil, ErrInvalidPayload
	}

	return st.payloadBuf[:nPl], nil
}

func (v *Verifier) validateHeader(h []byte, optKS ...*keySet) (int, error) {
	var ks *keySet
	if len(optKS) > 0 && optKS[0] != nil {
		ks = optKS[0]
	} else {
		ks = v.getKeySet()
	}
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
			afterComma := trimJSONWS(body[1:])
			if len(afterComma) == 0 || afterComma[0] != '"' {
				return -1, ErrInvalidHeader
			}
			body = afterComma
		}
		key, val, isStr, rest, ok := NextJSONProp(body)
		if !ok {
			return -1, ErrInvalidHeader
		}
		body = trimJSONWS(rest)
		switch string(key) {
		case "alg":
			if hasAlg || !isStr || string(val) != string(v.algBytes) {
				return -1, ErrInvalidHeader
			}
			hasAlg = true
		case "typ":
			if hasTyp || !isStr || len(val) != 3 || (val[0]|0x20) != 'j' || (val[1]|0x20) != 'w' || (val[2]|0x20) != 't' {
				return -1, ErrInvalidHeader
			}
			hasTyp = true
		case "crit":
			return -1, ErrInvalidHeader
		case "kid":
			if hasKid || !isStr || len(val) == 0 {
				return -1, ErrInvalidHeader
			}
			hasKid = true
			if bytes.IndexByte(val, '\\') >= 0 {
				val = UnescapeJSONInPlace(val)
			}
			keys := ks.keys
			if len(keys) > 0 {
				found := -1
				for i := range keys {
					if string(keys[i].idBytes) == string(val) {
						found = i
						break
					}
				}
				if found < 0 {
					return -1, ErrUnknownKeyID
				}
				keyIdx = found
			} else {
				return -1, ErrUnknownKeyID
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
		body = rest

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
				return ErrTokenExpired
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
				return ErrTokenNotValidYet
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
			if len(v.expectedIss) > 0 && string(val) != string(v.expectedIss) {
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

func equalJSONString(raw, expected []byte) bool {
	if bytes.IndexByte(raw, '\\') < 0 {
		return string(raw) == string(expected)
	}
	return equalJSONStringEscaped(raw, expected)
}

func equalJSONStringEscaped(raw, expected []byte) bool {
	var buf [MaxPayloadSize]byte
	n := copy(buf[:], raw)
	return string(UnescapeJSONInPlace(buf[:n])) == string(expected)
}

func matchAudienceClaim(val []byte, isStr bool, expectedAud []byte, capturedOut *[]byte) bool {
	if isStr {
		if len(expectedAud) > 0 && !equalJSONString(val, expectedAud) {
			return false
		}
		if capturedOut != nil {
			if bytes.IndexByte(val, '\\') >= 0 {
				val = UnescapeJSONInPlace(val)
			}
			*capturedOut = val
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
		elemMatched := len(expectedAud) > 0 && equalJSONString(elem, expectedAud)
		if elemMatched {
			matched = true
		}
		if capturedOut != nil && (first || elemMatched) {
			if bytes.IndexByte(elem, '\\') >= 0 {
				elem = UnescapeJSONInPlace(elem)
			}
			*capturedOut = elem
		}
		first = false
	}
	return matched
}

func encodeP1363ToDER(dst *[144]byte, r, s []byte, coordLen ...int) ([]byte, bool) {
	clen := 32
	if len(coordLen) > 0 {
		clen = coordLen[0]
	}
	return encodeP1363ToDERInto(dst[:], r, s, clen)
}

func encodeP1363ToDERInto(dst, r, s []byte, coordLen int) ([]byte, bool) {
	for len(r) > 0 && r[0] == 0 {
		r = r[1:]
	}
	for len(s) > 0 && s[0] == 0 {
		s = s[1:]
	}
	if len(r) == 0 || len(r) > coordLen || len(s) == 0 || len(s) > coordLen {
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

	if len(dst) < seqLen+3 {
		return nil, false
	}

	dst[0] = 0x30
	idx := 2
	if seqLen >= 128 {
		dst[1] = 0x81
		dst[2] = byte(seqLen)
		idx = 3
	} else {
		dst[1] = byte(seqLen)
	}
	dst[idx] = 0x02
	dst[idx+1] = byte(rLen)
	idx += 2
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

func decodeDERToP1363(der, dst []byte) bool {
	coordLen := len(dst) / 2
	if coordLen == 0 || len(dst)%2 != 0 || len(der) < 8 || der[0] != 0x30 {
		return false
	}
	idx := 2
	if der[1]&0x80 != 0 {
		idx++
	}
	if idx+1 >= len(der) || der[idx] != 0x02 {
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
	if len(rBytes) == 0 || len(rBytes) > coordLen || len(sBytes) == 0 || len(sBytes) > coordLen {
		return false
	}
	memclr(dst)
	copy(dst[coordLen-len(rBytes):coordLen], rBytes)
	copy(dst[2*coordLen-len(sBytes):2*coordLen], sBytes)
	return true
}
