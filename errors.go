package zerojwt

import "errors"

// Pre-allocated static errors returned by zerojwt.
// Comparing against these errors with errors.Is or == performs zero allocations.
var (
	// ErrMissingBearer is returned by VerifyBearer when the "Bearer " prefix is absent.
	ErrMissingBearer = errors.New("zerojwt: missing Bearer prefix")

	// ErrInvalidToken is returned when the token does not have 3 valid Base64URL segments.
	ErrInvalidToken = errors.New("zerojwt: malformed token structure")

	// ErrInvalidHeader is returned when the JWT header is not valid JSON or specifies an unsupported algorithm.
	ErrInvalidHeader = errors.New("zerojwt: invalid header or unsupported algorithm")

	// ErrInvalidSignature is returned when the cryptographic signature verification fails.
	ErrInvalidSignature = errors.New("zerojwt: signature verification failed")

	// ErrExpiredToken is returned when the current timestamp is >= the "exp" claim.
	ErrExpiredToken = errors.New("zerojwt: token is expired")

	// ErrNotValidYet is returned when the current timestamp is < the "nbf" claim.
	ErrNotValidYet = errors.New("zerojwt: token is not valid yet (nbf)")

	// ErrInvalidPayload is returned when the payload JSON is malformed or required claims are invalid.
	ErrInvalidPayload = errors.New("zerojwt: invalid token payload claims")

	// ErrPayloadTooLarge is returned when the decoded payload exceeds the configured MaxPayloadSize.
	ErrPayloadTooLarge = errors.New("zerojwt: payload exceeds maximum zero-alloc buffer size")

	// ErrInvalidIssuer is returned when the "iss" claim is missing or does not match ExpectedIssuer.
	ErrInvalidIssuer = errors.New("zerojwt: invalid or mismatched token issuer (iss)")

	// ErrInvalidAudience is returned when the "aud" claim is missing or does not match ExpectedAudience.
	ErrInvalidAudience = errors.New("zerojwt: invalid or mismatched token audience (aud)")

	// ErrUnknownKeyID is returned when the header specifies a "kid" that is not registered in the Verifier.
	ErrUnknownKeyID = errors.New("zerojwt: unknown key ID (kid) in header")
)
