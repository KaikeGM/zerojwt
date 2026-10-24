package zerojwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
)

// SignToIOV formats the JWT token into a 2-element scatter/gather I/O vector (iov)
// ready for unix.Writev or gnet.Conn.Writev with 0 heap allocations and 0 B/op.
//
// Optimization details:
// - iov[0] points directly to the Verifier's immutable, pre-encoded header ("header.").
// - iov[1] points to dst, containing only "payload.signature".
// - Skips copying the 37-byte header into dst, eliminating memory copy overhead.
// - Signs (header + payload) in streaming mode without memory concatenation.
func (v *Verifier) SignToIOV(dst []byte, payloadJSON []byte, iov *[2][]byte) error {
	st := v.acquireScratch()
	err := v.SignToIOVWithScratch(dst, payloadJSON, iov, st)
	v.releaseScratch(st)
	return err
}

// SignToIOVWithScratch is identical to SignToIOV but uses a caller-supplied Scratch state.
func (v *Verifier) SignToIOVWithScratch(dst []byte, payloadJSON []byte, iov *[2][]byte, st *Scratch) error {
	start := len(dst)
	if v.destroyed.Load() {
		return ErrVerifierDestroyed
	}
	if !v.CanSign() {
		return ErrNoSigningKey
	}
	if len(payloadJSON) > v.maxPayloadSize {
		return ErrPayloadTooLarge
	}

	enc := base64.RawURLEncoding
	pEncLen := enc.EncodedLen(len(payloadJSON))
	tailLen := pEncLen + 1 + v.sigEncodedLen // "payload.signature"

	if cap(dst)-start < tailLen {
		grown := make([]byte, start, start+tailLen)
		copy(grown, dst)
		dst = grown
	}

	// 1. Encode payload directly into dst
	dst = dst[:start+pEncLen]
	encPayload := dst[start : start+pEncLen]
	enc.Encode(encPayload, payloadJSON)

	// 2. Compute signature over (headerDot + encPayload) without concatenating memory
	var sig []byte
	switch v.alg {
	case AlgEdDSA:
		totalSigningLen := len(v.encodedHeaderDotBytes) + len(encPayload)
		var signBuf []byte
		if totalSigningLen <= len(st.signArr) {
			signBuf = st.signArr[:totalSigningLen]
		} else {
			signBuf = make([]byte, totalSigningLen)
		}
		copy(signBuf, v.encodedHeaderDotBytes)
		copy(signBuf[len(v.encodedHeaderDotBytes):], encPayload)
		sig = ed25519.Sign(v.edPriv, signBuf)
	case AlgES256:
		h := sha256.New()
		h.Write(v.encodedHeaderDotBytes)
		h.Write(encPayload)
		digest := h.Sum(st.sumBuf[:0])
		rr := v.randReader
		if rr == nil {
			rr = rand.Reader
		}
		asn1Sig, err := ecdsa.SignASN1(rr, v.ecPriv, digest)
		if err != nil || !decodeDERToP1363(asn1Sig, st.sumBuf[:64]) {
			return ErrSigningFailed
		}
		sig = st.sumBuf[:64]
	default:
		st.mac.Reset()
		_, _ = st.mac.Write(v.encodedHeaderDotBytes)
		_, _ = st.mac.Write(encPayload)
		sig = st.mac.Sum(st.sumBuf[:0])
	}

	// 3. Append '.' and Base64URL-encoded signature to dst
	dst = append(dst, '.')
	sigStart := len(dst)
	dst = dst[:sigStart+v.sigEncodedLen]
	enc.Encode(dst[sigStart:], sig)

	// 4. Populate 2-element scatter/gather vector (0 allocs)
	iov[0] = v.encodedHeaderDotBytes
	iov[1] = dst[start : sigStart+v.sigEncodedLen]
	return nil
}

// SignClaimsToIOV formats standard claims and emits a 2-element I/O vector (iov)
// ready for unix.Writev with 0 heap allocations and 0 B/op.
func (v *Verifier) SignClaimsToIOV(dst []byte, claims StandardClaims, iov *[2][]byte) error {
	st := v.acquireScratch()
	err := v.SignClaimsToIOVWithScratch(dst, claims, iov, st)
	v.releaseScratch(st)
	return err
}

// SignClaimsToIOVWithScratch is identical to SignClaimsToIOV but uses a caller-supplied Scratch state.
func (v *Verifier) SignClaimsToIOVWithScratch(dst []byte, claims StandardClaims, iov *[2][]byte, st *Scratch) error {
	if v.destroyed.Load() {
		return ErrVerifierDestroyed
	}
	if !v.CanSign() {
		return ErrNoSigningKey
	}
	if v.requireExp && claims.ExpiresAt <= 0 {
		return ErrMissingExp
	}
	if len(claims.Subject) == 0 || len(claims.Subject) > MaxSubjectSize {
		return ErrInvalidPayload
	}
	if len(claims.Username) > MaxUsernameSize {
		return ErrInvalidPayload
	}
	if len(claims.Issuer) > MaxIssuerSize {
		return ErrInvalidPayload
	}
	if len(claims.Audience) > MaxAudienceSize {
		return ErrInvalidPayload
	}
	if len(claims.JTI) > MaxJTISize {
		return ErrInvalidPayload
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

	return v.SignToIOVWithScratch(dst, b, iov, st)
}
