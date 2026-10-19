package zerojwt

import (
	"context"
	"net/http"
	"time"
	"unsafe"
)

type claimsContextKey struct{}

// ProtectFunc wraps a handler that receives stack-allocated *Claims directly,
// achieving 0 B/op and 0 allocs/op per authenticated HTTP request.
func (v *Verifier) ProtectFunc(next func(w http.ResponseWriter, r *http.Request, claims *Claims)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if len(auth) <= len(bearerPrefix) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		authBytes := unsafe.Slice(unsafe.StringData(auth), len(auth))
		var claims Claims
		if err := v.VerifyBearer(authBytes, time.Now().Unix(), &claims); err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r, &claims)
	}
}

// Middleware provides a standard net/http and chi compatible middleware that validates
// the Authorization: Bearer <token> header and attaches *Claims to the request's context.Context.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if len(auth) <= len(bearerPrefix) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		authBytes := unsafe.Slice(unsafe.StringData(auth), len(auth))
		var claims Claims
		if err := v.VerifyBearer(authBytes, time.Now().Unix(), &claims); err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), claimsContextKey{}, &claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ClaimsFromContext retrieves the verified *Claims from a request context populated by Verifier.Middleware.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(claimsContextKey{}).(*Claims)
	return c, ok
}
