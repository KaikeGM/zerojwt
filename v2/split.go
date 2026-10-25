package zerojwt

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"time"
)

// decodeBase64Split decodes a Base64URL string split across b1 and b2 directly into dst
// using only a 4-byte stack quantum for the boundary seam, with 0 heap allocations.
func decodeBase64Split(dst, b1, b2 []byte) (int, error) {
	if len(b1) == 0 {
		return rawURLStrict.Decode(dst, b2)
	}
	if len(b2) == 0 {
		return rawURLStrict.Decode(dst, b1)
	}

	// 1. Decode all complete 4-byte quanta from b1
	full1 := (len(b1) / 4) * 4
	n := 0
	var err error
	if full1 > 0 {
		n, err = rawURLStrict.Decode(dst, b1[:full1])
		if err != nil {
			return 0, err
		}
	}

	rem1 := b1[full1:]
	if len(rem1) > 0 {
		// 2. Stitch the boundary: rem1 + complement from b2
		need2 := 4 - len(rem1)
		if len(b2) < need2 {
			// Final unpadded block with total length < 4
			var tailQuantum [4]byte
			qLen := copy(tailQuantum[:], rem1)
			qLen += copy(tailQuantum[qLen:], b2)
			nQ, err := rawURLStrict.Decode(dst[n:], tailQuantum[:qLen])
			if err != nil {
				return 0, err
			}
			return n + nQ, nil
		}
		var quantum [4]byte
		copy(quantum[:], rem1)
		copy(quantum[len(rem1):], b2[:need2])
		nQ, err := rawURLStrict.Decode(dst[n:], quantum[:])
		if err != nil {
			return 0, err
		}
		n += nQ
		b2 = b2[need2:]
	}

	// 3. Decode remaining quanta from b2
	if len(b2) > 0 {
		n2, err := rawURLStrict.Decode(dst[n:], b2)
		if err != nil {
			return 0, err
		}
		n += n2
	}
	return n, nil
}

// VerifySplit validates a JWT token split across two non-contiguous memory segments
// (such as the head and tail of a circular ring buffer) with zero heap allocations.
func (v *Verifier) VerifySplit(head, tail []byte, now int64, claims *Claims) error {
	st := v.acquireScratch()
	err := v.VerifySplitWithScratch(head, tail, now, claims, st)
	v.releaseScratch(st)
	return err
}

// VerifySplitNow verifies a fragmented token across two non-contiguous byte slices using the current system Unix timestamp.
func (v *Verifier) VerifySplitNow(head, tail []byte, claims *Claims) error {
	return v.VerifySplit(head, tail, time.Now().Unix(), claims)
}

// VerifySplitWithScratch is identical to VerifySplit but uses a caller-supplied Scratch state.
func (v *Verifier) VerifySplitWithScratch(head, tail []byte, now int64, claims *Claims, st *Scratch) error {
	if len(head) == 0 {
		return v.VerifyWithScratch(tail, now, claims, st)
	}
	if len(tail) == 0 {
		return v.VerifyWithScratch(head, now, claims, st)
	}

	payload, err := v.verifySplitSignatureAndDecodePayload(head, tail, st)
	if err != nil {
		return err
	}
	return v.parseStandardClaims(payload, now, claims)
}

// VerifySplitAndIterate validates a token split across head and tail buffers and atomically
// invokes fn for each claim only if the entire token is cryptographically authentic and valid.
// If any validation rule fails, fn is never called and the error is returned immediately.
func (v *Verifier) VerifySplitAndIterate(head, tail []byte, now int64, fn func(key, val []byte, isStr bool) bool) error {
	st := v.acquireScratch()
	err := v.VerifySplitAndIterateWithScratch(head, tail, now, fn, st)
	v.releaseScratch(st)
	return err
}

// VerifySplitAndIterateWithScratch is identical to VerifySplitAndIterate but uses a caller-supplied Scratch state.
func (v *Verifier) VerifySplitAndIterateWithScratch(head, tail []byte, now int64, fn func(key, val []byte, isStr bool) bool, st *Scratch) error {
	if len(head) == 0 {
		return v.VerifyAndIterateWithScratch(tail, now, fn, st)
	}
	if len(tail) == 0 {
		return v.VerifyAndIterateWithScratch(head, now, fn, st)
	}

	payload, err := v.verifySplitSignatureAndDecodePayload(head, tail, st)
	if err != nil {
		return err
	}

	body, ok := TrimJSONObject(payload)
	if !ok {
		return ErrInvalidPayload
	}

	// Pass 1: Atomic cryptographic & claim validation
	if err := v.validatePayloadClaims(body, now); err != nil {
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

func (v *Verifier) verifySplitSignatureAndDecodePayload(head, tail []byte, st *Scratch) ([]byte, error) {
	if v.destroyed.Load() {
		return nil, ErrVerifierDestroyed
	}

	// Go's base64 decoder silently skips CR/LF; reject them so token has a single canonical representation
	if bytes.IndexByte(head, '\n') >= 0 || bytes.IndexByte(head, '\r') >= 0 ||
		bytes.IndexByte(tail, '\n') >= 0 || bytes.IndexByte(tail, '\r') >= 0 {
		return nil, ErrInvalidToken
	}

	// Identify the three segments across head and tail
	var (
		h1, h2       []byte
		p1, p2       []byte
		s1, s2       []byte
		hLen, pLen   int
		signingPart1 []byte
		signingPart2 []byte
	)

	dot1 := bytes.IndexByte(head, '.')
	if dot1 >= 0 {
		h1 = head[:dot1]
		hLen = len(h1)
		restHead := head[dot1+1:]
		dot2Head := bytes.IndexByte(restHead, '.')
		if dot2Head >= 0 {
			// Case 1: Both dots in head
			p1 = restHead[:dot2Head]
			pLen = len(p1)
			s1 = restHead[dot2Head+1:]
			s2 = tail
			if bytes.IndexByte(s1, '.') >= 0 || bytes.IndexByte(tail, '.') >= 0 {
				return nil, ErrInvalidToken
			}
			signingPart1 = head[:dot1+1+dot2Head]
		} else {
			// Case 2: Dot 1 in head, Dot 2 in tail
			dot2Tail := bytes.IndexByte(tail, '.')
			if dot2Tail < 0 {
				return nil, ErrInvalidToken
			}
			p1 = restHead
			p2 = tail[:dot2Tail]
			pLen = len(p1) + len(p2)
			s1 = tail[dot2Tail+1:]
			if bytes.IndexByte(s1, '.') >= 0 {
				return nil, ErrInvalidToken
			}
			signingPart1 = head
			signingPart2 = tail[:dot2Tail]
		}
	} else {
		// Case 3: Dot 1 in tail
		dot1Tail := bytes.IndexByte(tail, '.')
		if dot1Tail < 0 {
			return nil, ErrInvalidToken
		}
		h1 = head
		h2 = tail[:dot1Tail]
		hLen = len(h1) + len(h2)

		restTail := tail[dot1Tail+1:]
		dot2Tail := bytes.IndexByte(restTail, '.')
		if dot2Tail < 0 {
			return nil, ErrInvalidToken
		}
		p1 = restTail[:dot2Tail]
		pLen = len(p1)
		s1 = restTail[dot2Tail+1:]
		if bytes.IndexByte(s1, '.') >= 0 {
			return nil, ErrInvalidToken
		}
		signingPart1 = head
		signingPart2 = tail[:dot1Tail+1+dot2Tail]
	}

	enc := rawURLStrict
	sLen := len(s1) + len(s2)
	if hLen == 0 || pLen == 0 || sLen == 0 {
		return nil, ErrInvalidToken
	}

	// 1. Decode header
	if enc.DecodedLen(hLen) > len(st.hdrBuf) {
		return nil, ErrHeaderTooLarge
	}
	nHdr, err := decodeBase64Split(st.hdrBuf, h1, h2)
	if err != nil || nHdr == 0 {
		return nil, ErrInvalidHeader
	}
	ks := v.getKeySet()
	keyIdx, err := v.validateHeader(st.hdrBuf[:nHdr], ks)
	if err != nil {
		return nil, err
	}

	// 2. Enforce payload size bound before signature hashing/stitching (prevents CPU and heap allocation DoS)
	if enc.DecodedLen(pLen) > len(st.payloadBuf) {
		return nil, ErrPayloadTooLarge
	}

	// 3. Decode signature
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

	if enc.DecodedLen(sLen) > len(st.sigBuf) {
		return nil, ErrInvalidSignature
	}
	nSig, err := decodeBase64Split(st.sigBuf[:], s1, s2)
	if err != nil || nSig != expectedSigLen {
		return nil, ErrInvalidSignature
	}

	// 4. Verify signature
	switch v.alg {
	case AlgEdDSA:
		pub := v.edPub
		if keyIdx >= 0 {
			pub = ks.keys[keyIdx].ed25519Public
		}
		if len(pub) != 32 {
			return nil, ErrInvalidSignature
		}
		signInput := stitchSigningInput(st, signingPart1, signingPart2)
		if !ed25519.Verify(pub, signInput, st.sigBuf[:64]) {
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
		signInput := stitchSigningInput(st, signingPart1, signingPart2)
		digest := sha256.Sum256(signInput)
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
		signInput := stitchSigningInput(st, signingPart1, signingPart2)
		digest := sha512.Sum384(signInput)
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
		signInput := stitchSigningInput(st, signingPart1, signingPart2)
		digest := sha512.Sum512(signInput)
		if !ecdsa.VerifyASN1(pub, digest[:], derSig) {
			return nil, ErrInvalidSignature
		}
	case AlgRS256:
		signInput := stitchSigningInput(st, signingPart1, signingPart2)
		digest := sha256.Sum256(signInput)
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
		_, _ = mac.Write(signingPart1)
		if len(signingPart2) > 0 {
			_, _ = mac.Write(signingPart2)
		}
		calculated := mac.Sum(st.sumBuf[:0])
		if !hmac.Equal(st.sigBuf[:v.sigDecodedLen], calculated) {
			return nil, ErrInvalidSignature
		}
	}

	// 5. Decode payload
	nPl, err := decodeBase64Split(st.payloadBuf, p1, p2)
	if err != nil || nPl == 0 {
		return nil, ErrInvalidPayload
	}

	return st.payloadBuf[:nPl], nil
}

func stitchSigningInput(st *Scratch, part1, part2 []byte) []byte {
	if len(part2) == 0 {
		return part1
	}
	totalLen := len(part1) + len(part2)
	var signInput []byte
	if totalLen <= len(st.signArr) {
		signInput = st.signArr[:totalLen]
	} else {
		signInput = make([]byte, totalLen)
	}
	copy(signInput, part1)
	copy(signInput[len(part1):], part2)
	return signInput
}
