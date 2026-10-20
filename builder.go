package zerojwt

import "strconv"

// SignBuilder is a stack-allocated, zero-allocation fluent builder for constructing
// and signing JWT tokens with arbitrary custom claims.
type SignBuilder struct {
	v      *Verifier
	st     *Scratch
	dst    []byte
	buf    []byte
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
		owned: false,
	}
}

func (b *SignBuilder) appendKey(key string) {
	if b.hasAny {
		b.buf = append(b.buf, ',')
	}
	b.hasAny = true
	b.buf = AppendEscapedJSONString(b.buf, []byte(key))
	b.buf = append(b.buf, ':')
}

// SetSubject appends the standard "sub" claim.
func (b *SignBuilder) SetSubject(sub []byte) *SignBuilder {
	return b.SetClaimBytes("sub", sub)
}

// SetUsername appends the "username" claim.
func (b *SignBuilder) SetUsername(username []byte) *SignBuilder {
	return b.SetClaimBytes("username", username)
}

// SetIssuer appends the standard "iss" claim.
func (b *SignBuilder) SetIssuer(iss []byte) *SignBuilder {
	return b.SetClaimBytes("iss", iss)
}

// SetAudience appends the standard "aud" claim.
func (b *SignBuilder) SetAudience(aud []byte) *SignBuilder {
	return b.SetClaimBytes("aud", aud)
}

// SetJTI appends the standard "jti" (JWT ID) claim.
func (b *SignBuilder) SetJTI(jti []byte) *SignBuilder {
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

// SetClaimBytes appends a custom string claim from a byte slice with JSON escaping.
func (b *SignBuilder) SetClaimBytes(key string, val []byte) *SignBuilder {
	b.appendKey(key)
	b.buf = AppendEscapedJSONString(b.buf, val)
	return b
}

// SetClaimString appends a custom string claim with JSON escaping.
func (b *SignBuilder) SetClaimString(key, val string) *SignBuilder {
	b.appendKey(key)
	b.buf = AppendEscapedJSONString(b.buf, []byte(val))
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
// The value is copied verbatim and NOT validated or escaped: never pass untrusted input,
// or the resulting payload may be malformed or contain injected claims.
func (b *SignBuilder) SetClaimRawJSON(key string, rawJSON []byte) *SignBuilder {
	b.appendKey(key)
	b.buf = append(b.buf, rawJSON...)
	return b
}

// Discard releases the internal Scratch buffer back to the pool if owned,
// invalidating the builder. It is safe to call Discard multiple times or after Sign.
// Typical usage:
//
//	b := v.NewSigner(dst)
//	defer b.Discard()
func (b *SignBuilder) Discard() {
	if b.owned && b.st != nil {
		b.v.releaseScratch(b.st)
		b.st = nil
	}
}

// Sign finalizes the JSON payload, signs the token into dst, and returns the resulting slice.
// If the SignBuilder was created via NewSigner, the internal Scratch is returned to the pool.
func (b *SignBuilder) Sign() ([]byte, error) {
	if b.st == nil {
		return nil, ErrInvalidPayload
	}
	defer b.Discard()
	if len(b.buf)+1 > len(b.st.payloadBuf) {
		return nil, ErrPayloadTooLarge
	}
	if b.v.requireExp && !b.hasExp {
		return nil, ErrMissingExp
	}
	b.buf = append(b.buf, '}')
	tok := b.v.SignHS256WithScratch(b.dst, b.buf, b.st)
	if tok == nil {
		return nil, ErrNoSigningKey
	}
	return tok, nil
}
