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

// Middleware provides a standard net/http compatible middleware that validates
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

// FromContext retrieves the verified *Claims from a request context, returning nil if not present.
func FromContext(ctx context.Context) *Claims {
	c, _ := ClaimsFromContext(ctx)
	return c
}

// ForwardAuthOptions configures the ForwardAuth HTTP handler for reverse proxies
// such as Nginx (ngx_http_auth_request_module) and Traefik ForwardAuth.
type ForwardAuthOptions struct {
	// CookieName is the optional cookie name to extract the JWT token from if the
	// Authorization header is missing (e.g. "access_token" or "jwt").
	CookieName string

	// CustomHeader is an optional alternative header containing the token directly (e.g. "X-Auth-Token").
	CustomHeader string

	// UserHeader specifies the response header name for the username/subject on 200 OK.
	// Defaults to "X-Auth-User" if empty. Set to "-" to suppress.
	UserHeader string

	// SubHeader specifies the response header name for the "sub" claim on 200 OK.
	// Defaults to "X-Auth-Sub" if empty. Set to "-" to suppress.
	SubHeader string

	// PopulateHeaders is an optional callback to populate additional response headers
	// from custom claims or standard claims before returning 200 OK.
	PopulateHeaders func(w http.ResponseWriter, r *http.Request, claims *Claims)
}

// ForwardAuthHandler returns an http.HandlerFunc designed for edge reverse proxies
// like Nginx (ngx_http_auth_request_module) and Traefik ForwardAuth.
//
// On successful verification, it responds with HTTP 200 OK and sets downstream
// authentication headers (such as X-Auth-User and X-Auth-Sub) for upstream injection.
// If verification fails or the token is missing/expired, it responds with HTTP 401 Unauthorized.
func (v *Verifier) ForwardAuthHandler(opts ...ForwardAuthOptions) http.HandlerFunc {
	var opt ForwardAuthOptions
	if len(opts) > 0 {
		opt = opts[0]
	}
	userHdr := opt.UserHeader
	if userHdr == "" {
		userHdr = "X-Auth-User"
	}
	subHdr := opt.SubHeader
	if subHdr == "" {
		subHdr = "X-Auth-Sub"
	}

	return func(w http.ResponseWriter, r *http.Request) {
		var (
			claims Claims
			err    error
			now    = time.Now().Unix()
		)

		auth := r.Header.Get("Authorization")
		if len(auth) > len(bearerPrefix) {
			authBytes := unsafe.Slice(unsafe.StringData(auth), len(auth))
			err = v.VerifyBearer(authBytes, now, &claims)
		} else if opt.CustomHeader != "" && r.Header.Get(opt.CustomHeader) != "" {
			tok := r.Header.Get(opt.CustomHeader)
			tokBytes := unsafe.Slice(unsafe.StringData(tok), len(tok))
			err = v.Verify(tokBytes, now, &claims)
		} else if opt.CookieName != "" {
			if cookie, cErr := r.Cookie(opt.CookieName); cErr == nil && len(cookie.Value) > 0 {
				tokBytes := unsafe.Slice(unsafe.StringData(cookie.Value), len(cookie.Value))
				err = v.Verify(tokBytes, now, &claims)
			} else {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		} else {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if userHdr != "-" {
			if claims.HasUsername {
				w.Header().Set(userHdr, string(claims.Username()))
			} else if claims.HasSub {
				w.Header().Set(userHdr, string(claims.Subject()))
			}
		}
		if subHdr != "-" && claims.HasSub {
			w.Header().Set(subHdr, string(claims.Subject()))
		}

		if opt.PopulateHeaders != nil {
			opt.PopulateHeaders(w, r, &claims)
		}

		w.WriteHeader(http.StatusOK)
	}
}
