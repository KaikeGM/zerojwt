package zerojwt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"math/big"
)

// ParseJWKS parses a JSON Web Key Set (RFC 7517) JSON document into a slice of Key structs.
// It operates with zero external dependencies and enforces cryptographic parameter validity
// (e.g. NIST P-256 curve checks, Ed25519 32-byte public key length, non-empty symmetric keys).
func ParseJWKS(jwks []byte) ([]Key, error) {
	body, ok := TrimJSONObject(jwks)
	if !ok {
		return nil, ErrInvalidJWKS
	}

	var keysArr []byte
	foundKeys := false
	for len(body) > 0 {
		k, val, _, rest, ok := NextJSONProp(body)
		if !ok {
			return nil, ErrInvalidJWKS
		}
		body = trimJSONWS(rest)
		if string(k) == "keys" {
			keysArr = val
			foundKeys = true
			break
		}
	}
	if !foundKeys {
		return nil, ErrInvalidJWKS
	}

	arrBody, ok := TrimJSONArray(keysArr)
	if !ok {
		return nil, ErrInvalidJWKS
	}

	var res []Key
	seenKids := make(map[string]struct{})
	for len(arrBody) > 0 {
		elem, _, rest, ok := NextArrayElement(arrBody)
		if !ok {
			return nil, ErrInvalidJWKS
		}
		arrBody = rest
		elemObj, ok := TrimJSONObject(elem)
		if !ok {
			return nil, ErrInvalidJWKS
		}

		var (
			kty, kid, crv, k, x, y, use, alg, keyOps []byte
			hasUse, hasKeyOps                        bool
		)
		for len(elemObj) > 0 {
			propKey, propVal, isStr, restProp, ok := NextJSONProp(elemObj)
			if !ok {
				return nil, ErrInvalidJWKS
			}
			elemObj = trimJSONWS(restProp)
			if string(propKey) == "key_ops" {
				if isStr {
					return nil, ErrInvalidJWKS
				}
				keyOps = propVal
				hasKeyOps = true
				continue
			}
			if !isStr {
				switch string(propKey) {
				case "kty", "use", "alg", "kid", "crv", "k", "x", "y":
					return nil, ErrInvalidJWKS
				}
				continue
			}
			if bytes.IndexByte(propVal, '\\') >= 0 {
				buf := make([]byte, len(propVal))
				copy(buf, propVal)
				propVal = UnescapeJSONInPlace(buf)
			}
			switch string(propKey) {
			case "kty":
				kty = propVal
			case "use":
				use = propVal
				hasUse = true
			case "alg":
				if len(propVal) == 0 {
					return nil, ErrInvalidJWKS
				}
				alg = propVal
			case "kid":
				kid = propVal
			case "crv":
				crv = propVal
			case "k":
				k = propVal
			case "x":
				x = propVal
			case "y":
				y = propVal
			}
		}

		if hasUse && string(use) != "sig" && string(use) != "enc" {
			return nil, ErrInvalidJWKS
		}
		if hasKeyOps {
			canVerify, ok := validateJWKSKeyOps(keyOps, use)
			if !ok {
				return nil, ErrInvalidJWKS
			}
			if !canVerify {
				continue
			}
		}
		if string(use) == "enc" {
			continue
		}

		switch string(kty) {
		case "oct":
			if len(kid) == 0 || len(k) == 0 || (len(alg) > 0 && string(alg) != "HS256" && string(alg) != "HS384" && string(alg) != "HS512") {
				return nil, ErrInvalidJWKS
			}
			sec, err := decodeJWKSBase64(k)
			if err != nil || len(sec) == 0 {
				return nil, ErrInvalidJWKS
			}
			res = append(res, Key{
				ID:     string(kid),
				Secret: sec,
			})
		case "OKP":
			if len(kid) == 0 || string(crv) != "Ed25519" || len(x) == 0 || (len(alg) > 0 && string(alg) != "EdDSA") {
				return nil, ErrInvalidJWKS
			}
			pubBytes, err := decodeJWKSBase64(x)
			if err != nil || len(pubBytes) != ed25519.PublicKeySize {
				return nil, ErrInvalidJWKS
			}
			res = append(res, Key{
				ID:            string(kid),
				Ed25519Public: ed25519.PublicKey(pubBytes),
			})
		case "EC":
			if len(kid) == 0 || string(crv) != "P-256" || len(x) == 0 || len(y) == 0 || (len(alg) > 0 && string(alg) != "ES256") {
				return nil, ErrInvalidJWKS
			}
			// RFC 7518 §6.2.1.2 & §6.2.1.3: P-256 coordinates MUST be exactly 32 octets.
			xBytes, err := decodeJWKSBase64(x)
			if err != nil || len(xBytes) != 32 {
				return nil, ErrInvalidJWKS
			}
			yBytes, err := decodeJWKSBase64(y)
			if err != nil || len(yBytes) != 32 {
				return nil, ErrInvalidJWKS
			}
			pub := &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     new(big.Int).SetBytes(xBytes),
				Y:     new(big.Int).SetBytes(yBytes),
			}
			if !isValidP256PublicKey(pub) {
				return nil, ErrInvalidJWKS
			}
			res = append(res, Key{
				ID:          string(kid),
				ECDSAPublic: pub,
			})
		default:
			// RFC 7517 §5: ignore unsupported key types (e.g. RSA) without failing the whole JWKS document.
			continue
		}

		if _, dup := seenKids[string(kid)]; dup {
			return nil, ErrInvalidJWKS
		}
		seenKids[string(kid)] = struct{}{}
	}

	if len(res) == 0 {
		return nil, ErrInvalidJWKS
	}
	return res, nil
}

func validateJWKSKeyOps(keyOps, use []byte) (canVerify bool, ok bool) {
	opsBody, ok := TrimJSONArray(keyOps)
	if !ok || len(opsBody) == 0 {
		return false, false
	}
	hasSigOp := false
	hasEncOp := false
	for len(opsBody) > 0 {
		op, isStr, rest, ok := NextArrayElement(opsBody)
		if !ok || !isStr || len(op) == 0 {
			return false, false
		}
		opsBody = rest
		switch string(op) {
		case "verify":
			canVerify = true
			hasSigOp = true
		case "sign":
			hasSigOp = true
		case "encrypt", "decrypt", "wrapKey", "unwrapKey", "deriveKey", "deriveBits":
			hasEncOp = true
		default:
			return false, false
		}
	}
	if (string(use) == "sig" && hasEncOp) || (string(use) == "enc" && hasSigOp) {
		return false, false
	}
	return canVerify, true
}

func decodeJWKSBase64(b []byte) ([]byte, error) {
	if bytes.IndexByte(b, '\n') >= 0 || bytes.IndexByte(b, '\r') >= 0 {
		return nil, ErrInvalidJWKS
	}
	b = bytes.TrimRight(b, "=")
	dst := make([]byte, rawURLStrict.DecodedLen(len(b)))
	n, err := rawURLStrict.Decode(dst, b)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

// UpdateKeysFromJWKS parses a JWKS (RFC 7517) JSON document and atomically
// replaces the Verifier's key store in place without downtime.
func (v *Verifier) UpdateKeysFromJWKS(jwks []byte) error {
	keys, err := ParseJWKS(jwks)
	if err != nil {
		return err
	}
	return v.UpdateKeys(keys)
}
