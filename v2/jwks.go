package zerojwt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
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
		body = bytes.TrimSpace(rest)
		if bytes.Equal(k, []byte("keys")) {
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
			kty, kid, crv, k, x, y []byte
		)
		for len(elemObj) > 0 {
			propKey, propVal, isStr, restProp, ok := NextJSONProp(elemObj)
			if !ok {
				return nil, ErrInvalidJWKS
			}
			elemObj = bytes.TrimSpace(restProp)
			if !isStr {
				continue
			}
			if bytes.IndexByte(propVal, '\\') >= 0 {
				propVal = UnescapeJSONInPlace(propVal)
			}
			switch string(propKey) {
			case "kty":
				kty = propVal
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

		if len(kid) == 0 {
			return nil, ErrInvalidJWKS
		}

		switch string(kty) {
		case "oct":
			if len(k) == 0 {
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
			if string(crv) != "Ed25519" || len(x) == 0 {
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
			if string(crv) != "P-256" || len(x) == 0 || len(y) == 0 {
				return nil, ErrInvalidJWKS
			}
			xBytes, err := decodeJWKSBase64(x)
			if err != nil || len(xBytes) == 0 {
				return nil, ErrInvalidJWKS
			}
			yBytes, err := decodeJWKSBase64(y)
			if err != nil || len(yBytes) == 0 {
				return nil, ErrInvalidJWKS
			}
			xInt := new(big.Int).SetBytes(xBytes)
			yInt := new(big.Int).SetBytes(yBytes)
			if !elliptic.P256().IsOnCurve(xInt, yInt) {
				return nil, ErrInvalidJWKS
			}
			res = append(res, Key{
				ID: string(kid),
				ECDSAPublic: &ecdsa.PublicKey{
					Curve: elliptic.P256(),
					X:     xInt,
					Y:     yInt,
				},
			})
		default:
			return nil, ErrInvalidJWKS
		}
	}

	return res, nil
}

func decodeJWKSBase64(b []byte) ([]byte, error) {
	b = bytes.TrimRight(b, "=")
	dst := make([]byte, base64.RawURLEncoding.DecodedLen(len(b)))
	n, err := base64.RawURLEncoding.Decode(dst, b)
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
