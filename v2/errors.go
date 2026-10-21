package zerojwt

import "errors"

var (
	// ErrInvalidToken indicates the token string is malformed (e.g. wrong number of segments, non-Base64URL characters).
	ErrInvalidToken = errors.New("zerojwt: invalid token format")

	// ErrInvalidHeader indicates the token header is missing, malformed, or specifies an unsupported algorithm.
	ErrInvalidHeader = errors.New("zerojwt: invalid or malformed header")

	// ErrInvalidPayload indicates the payload JSON is malformed or contains claims exceeding maximum field bounds.
	ErrInvalidPayload = errors.New("zerojwt: invalid payload")

	// ErrInvalidSignature indicates cryptographic signature verification failed (forged, corrupted, or signed with a different key).
	ErrInvalidSignature = errors.New("zerojwt: signature verification failed")

	// ErrTokenExpired indicates the current timestamp is greater than the token's "exp" claim (accounting for Leeway).
	ErrTokenExpired = errors.New("zerojwt: token has expired")

	// ErrTokenNotValidYet indicates the current timestamp is before the token's "nbf" claim (accounting for Leeway).
	ErrTokenNotValidYet = errors.New("zerojwt: token is not valid yet")

	// ErrMissingExp indicates the token payload omits an "exp" claim when RequireExp is enabled.
	ErrMissingExp = errors.New("zerojwt: missing required exp claim")

	// ErrPayloadTooLarge indicates the decoded payload exceeds the configured MaxPayloadSize.
	ErrPayloadTooLarge = errors.New("zerojwt: payload exceeds maximum size")

	// ErrHeaderTooLarge indicates the decoded header exceeds the configured MaxHeaderSize.
	ErrHeaderTooLarge = errors.New("zerojwt: header exceeds maximum size")

	// ErrUnknownKeyID indicates the token contains a "kid" header that was not registered in Verifier's key store.
	ErrUnknownKeyID = errors.New("zerojwt: unknown key ID in kid header")

	// ErrInvalidConfig indicates an unusable Verifier configuration (e.g. short secret, invalid ECDSA curve).
	ErrInvalidConfig = errors.New("zerojwt: invalid verifier configuration")

	// ErrVerifierDestroyed indicates the Verifier was invalidated via Destroy() and cannot verify or sign tokens.
	ErrVerifierDestroyed = errors.New("zerojwt: verifier has been destroyed")

	// ErrInvalidIssuer indicates the token's "iss" claim does not match the ExpectedIssuer configuration.
	ErrInvalidIssuer = errors.New("zerojwt: issuer does not match ExpectedIssuer")

	// ErrInvalidAudience indicates the token's "aud" claim does not match the ExpectedAudience configuration.
	ErrInvalidAudience = errors.New("zerojwt: audience does not match ExpectedAudience")

	// ErrNoSigningKey indicates the Verifier does not hold a private key and cannot sign tokens.
	ErrNoSigningKey = errors.New("zerojwt: verifier holds no signing key")

	// ErrSigningFailed indicates a low-level cryptographic signing failure occurred during token emission.
	ErrSigningFailed = errors.New("zerojwt: cryptographic signing failed")

	// ErrMismatchedKeyPair indicates the provided public and private keys do not form a mathematically matching key pair.
	ErrMismatchedKeyPair = errors.New("zerojwt: public and private keys do not form a matching cryptographic key pair")

	// ErrMissingBearer indicates an Authorization header does not begin with the required "Bearer " prefix.
	ErrMissingBearer = errors.New("zerojwt: missing or invalid Bearer prefix")

	// Compatibility aliases for v1 error identifiers
	ErrExpiredToken = ErrTokenExpired
	ErrNotValidYet  = ErrTokenNotValidYet
)
