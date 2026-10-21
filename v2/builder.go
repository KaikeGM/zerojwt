package zerojwt

import (
	"strconv"
)

// SignBuilder is a stack-allocated, zero-allocation fluent builder for constructing
// and signing JWT tokens with arbitrary custom claims.
type SignBuilder struct {
	v      *Verifier
	st     *Scratch
	dst    []byte
	buf    []byte
	start  int
	hasAny bool
	hasExp bool
	owned  bool
}

// NewSigner creates a fluent SignBuilder backed by the Verifier's Scratch pool.
// Calling Sign() automatically releases the internal Scratch back to the pool.
func (v *Verifier) NewSigner(dst []byte) SignBuilder {
	st := v.pool.Get().(*Scratch)
	b := st.payloadBuf[:0]
	b = append(b, '{')
	return SignBuilder{
		v:     v,
		st:    st,
		dst:   dst,
		buf:   b,
		start: len(dst),
		owned: true,
	}
}

// NewSignerWithScratch creates a fluent SignBuilder using a caller-supplied Scratch
// (ideal for single-threaded event loops like gnet).
func (v *Verifier) NewSignerWithScratch(dst []byte, st *Scratch) SignBuilder {
	b := st.payloadBuf[:0]
	b = append(b, '{')
	return SignBuilder{
		v:     v,
		st:    st,
		dst:   dst,
		buf:   b,
		start: len(dst),
		owned: false,
	}
}

func (b *SignBuilder) appendKey(key string) {
	if b.hasAny {
		b.buf = append(b.buf, ',')
	}
	b.hasAny = true
	b.buf = AppendEscapedJSON(b.buf, key)
	b.buf = append(b.buf, ':')
}

// SetSubject appends the standard "sub" claim from a string with 0 allocs.
func (b *SignBuilder) SetSubject(sub string) *SignBuilder {
	return b.SetClaimString("sub", sub)
}

// SetSubjectBytes appends the standard "sub" claim from a byte slice with 0 allocs.
func (b *SignBuilder) SetSubjectBytes(sub []byte) *SignBuilder {
	return b.SetClaimBytes("sub", sub)
}

// SetUsername appends the "username" claim from a string.
func (b *SignBuilder) SetUsername(username string) *SignBuilder {
	return b.SetClaimString("username", username)
}

// SetUsernameBytes appends the "username" claim from a byte slice.
func (b *SignBuilder) SetUsernameBytes(username []byte) *SignBuilder {
	return b.SetClaimBytes("username", username)
}

// SetIssuer appends the standard "iss" claim from a string.
func (b *SignBuilder) SetIssuer(iss string) *SignBuilder {
	return b.SetClaimString("iss", iss)
}

// SetIssuerBytes appends the standard "iss" claim from a byte slice.
func (b *SignBuilder) SetIssuerBytes(iss []byte) *SignBuilder {
	return b.SetClaimBytes("iss", iss)
}

// SetAudience appends the standard "aud" claim from a string.
func (b *SignBuilder) SetAudience(aud string) *SignBuilder {
	return b.SetClaimString("aud", aud)
}

// SetAudienceBytes appends the standard "aud" claim from a byte slice.
func (b *SignBuilder) SetAudienceBytes(aud []byte) *SignBuilder {
	return b.SetClaimBytes("aud", aud)
}

// SetJTI appends the standard "jti" (JWT ID) claim from a string.
func (b *SignBuilder) SetJTI(jti string) *SignBuilder {
	return b.SetClaimString("jti", jti)
}

// SetJTIBytes appends the standard "jti" (JWT ID) claim from a byte slice.
func (b *SignBuilder) SetJTIBytes(jti []byte) *SignBuilder {
	return b.SetClaimBytes("jti", jti)
}

// SetIssuedAt appends the standard "iat" claim (Unix seconds).
func (b *SignBuilder) SetIssuedAt(iat int64) *SignBuilder {
	return b.SetClaimInt("iat", iat)
}

// SetExpiresAt appends the standard "exp" claim (Unix seconds).
func (b *SignBuilder) SetExpiresAt(exp int64) *SignBuilder {
	b.hasExp = true
	return b.SetClaimInt("exp", exp)
}

// SetNotBefore appends the standard "nbf" claim (Unix seconds).
func (b *SignBuilder) SetNotBefore(nbf int64) *SignBuilder {
	return b.SetClaimInt("nbf", nbf)
}

// SetClaimBytes appends a custom string claim from a byte slice with zero allocations.
func (b *SignBuilder) SetClaimBytes(key string, val []byte) *SignBuilder {
	b.appendKey(key)
	b.buf = AppendEscapedJSON(b.buf, val)
	return b
}

// SetClaimString appends a custom string claim with zero allocations even for strings > 32 bytes (UUIDs).
func (b *SignBuilder) SetClaimString(key, val string) *SignBuilder {
	b.appendKey(key)
	b.buf = AppendEscapedJSON(b.buf, val)
	return b
}

// SetClaimInt appends a custom 64-bit integer claim.
func (b *SignBuilder) SetClaimInt(key string, val int64) *SignBuilder {
	b.appendKey(key)
	b.buf = strconv.AppendInt(b.buf, val, 10)
	return b
}

// SetClaimBool appends a custom boolean claim.
func (b *SignBuilder) SetClaimBool(key string, val bool) *SignBuilder {
	b.appendKey(key)
	if val {
		b.buf = append(b.buf, "true"...)
	} else {
		b.buf = append(b.buf, "false"...)
	}
	return b
}

// SetClaimRawJSON appends a pre-formatted JSON value (such as an array `["admin","editor"]` or object).
// The value is copied verbatim and NOT validated or escaped: never pass untrusted input.
func (b *SignBuilder) SetClaimRawJSON(key string, rawJSON []byte) *SignBuilder {
	b.appendKey(key)
	b.buf = append(b.buf, rawJSON...)
	return b
}

// Discard releases internal Scratch buffer back to pool if owned, invalidating the builder.
// It is safe to call Discard multiple times or after Sign.
func (b *SignBuilder) Discard() {
	if b.owned && b.st != nil && b.v != nil {
		b.v.releaseScratch(b.st)
		b.st = nil
	}
}

// Sign finalizes the JSON payload, signs the token into dst, and returns the resulting slice.
// If the SignBuilder was created via NewSigner, internal Scratch is returned to the pool.
// On error, dst is rolled back to its original length, preserving caller's buffer capacity.
func (b *SignBuilder) Sign() ([]byte, error) {
	if b.st == nil {
		return b.dst[:b.start], ErrInvalidPayload
	}
	defer b.Discard()
	if len(b.buf)+1 > len(b.st.payloadBuf) {
		return b.dst[:b.start], ErrPayloadTooLarge
	}
	if b.v.requireExp && !b.hasExp {
		return b.dst[:b.start], ErrMissingExp
	}
	b.buf = append(b.buf, '}')
	return b.v.SignWithScratch(b.dst, b.buf, b.st)
}
