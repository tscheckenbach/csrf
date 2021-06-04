package csrf

import (
	"encoding/base64"
	"fmt"
	"github.com/gorilla/securecookie"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"net/http"
	"net/url"
)

// CSRF token length in bytes.
const tokenLength = 32

// Context/session keys & prefixes
const (
	tokenKey     string = "gorilla.csrf.Token"
	formKey      string = "gorilla.csrf.Form"
	errorKey     string = "gorilla.csrf.Error"
	skipCheckKey string = "gorilla.csrf.Skip"
	cookieName   string = "_gorilla_csrf"
	errorPrefix  string = "gorilla/csrf: "
)

var (
	// The name value used in form fields.
	fieldName = tokenKey
	// defaultAge sets the default MaxAge for cookies.
	defaultAge = 3600 * 12
	// The default HTTP request header to inspect
	headerName = "X-CSRF-Token"
	// Idempotent (safe) methods as defined by RFC7231 section 4.2.2.
	safeMethods = []string{"GET", "HEAD", "OPTIONS", "TRACE"}
)

// TemplateTag provides a default template tag - e.g. {{ .csrfField }} - for use
// with the TemplateField function.
var TemplateTag = "csrfField"

var (
	// ErrNoReferer is returned when a HTTPS request provides an empty Referer
	// header.
	ErrNoReferer = errors.New("referer not supplied")
	// ErrBadReferer is returned when the scheme & host in the URL do not match
	// the supplied Referer header.
	ErrBadReferer = errors.New("referer invalid")
	// ErrNoToken is returned if no CSRF token is supplied in the request.
	ErrNoToken = errors.New("CSRF token not found in request")
	// ErrBadToken is returned if the CSRF token in the request does not match
	// the token in the session, or is otherwise malformed.
	ErrBadToken = errors.New("CSRF token invalid")
)

// SameSiteMode allows a server to define a cookie attribute making it impossible for
// the browser to send this cookie along with cross-site requests. The main
// goal is to mitigate the risk of cross-origin information leakage, and provide
// some protection against cross-site request forgery attacks.
//
// See https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site-00 for details.
type SameSiteMode int

// SameSite options
const (
	// SameSiteDefaultMode sets the `SameSite` cookie attribute, which is
	// invalid in some older browsers due to changes in the SameSite spec. These
	// browsers will not send the cookie to the server.
	// csrf uses SameSiteLaxMode (SameSite=Lax) as the default as of v1.7.0+
	SameSiteDefaultMode SameSiteMode = iota + 1
	SameSiteLaxMode
	SameSiteStrictMode
	SameSiteNoneMode
)

type Csrf struct {
	sc   *securecookie.SecureCookie
	st   store
	opts options
}

// options contains the optional settings for the CSRF middleware.
type options struct {
	MaxAge int
	Domain string
	Path   string
	// Note that the function and field names match the case of the associated
	// http.Cookie field instead of the "correct" HTTPOnly name that golint suggests.
	HttpOnly       bool
	Secure         bool
	SameSite       SameSiteMode
	RequestHeader  string
	FieldName      string
	ErrorHandler   http.Handler
	CookieName     string
	TrustedOrigins []string
	TrustedTokens  []string
}

// Protect is HTTP middleware that provides Cross-Site Request Forgery
// protection.
//
// It securely generates a masked (unique-per-request) token that
// can be embedded in the HTTP response (e.g. form field or HTTP header).
// The original (unmasked) token is stored in the session, which is inaccessible
// by an attacker (provided you are using HTTPS). Subsequent requests are
// expected to include this token, which is compared against the session token.
// Requests that do not provide a matching token are served with a HTTP 403
// 'Forbidden' error response.
//
// Example:
//	package main
//
//	import (
//		"html/template"
//
//		"github.com/gorilla/csrf"
//		"github.com/gorilla/mux"
//	)
//
//	var t = template.Must(template.New("signup_form.tmpl").Parse(form))
//
//	func main() {
//		r := mux.NewRouter()
//
//		r.HandleFunc("/signup", GetSignupForm)
//		// POST requests without a valid token will return a HTTP 403 Forbidden.
//		r.HandleFunc("/signup/post", PostSignupForm)
//
//		// Add the middleware to your router.
//		http.ListenAndServe(":8000",
//		// Note that the authentication key provided should be 32 bytes
//		// long and persist across application restarts.
//			  csrf.Protect([]byte("32-byte-long-auth-key"))(r))
//	}
//
//	func GetSignupForm(w http.ResponseWriter, r *http.Request) {
//		// signup_form.tmpl just needs a {{ .csrfField }} template tag for
//		// csrf.TemplateField to inject the CSRF token into. Easy!
//		t.ExecuteTemplate(w, "signup_form.tmpl", map[string]interface{}{
//			csrf.TemplateTag: csrf.TemplateField(r),
//		})
//		// We could also retrieve the token directly from csrf.Token(r) and
//		// set it in the request header - w.Header.Set("X-CSRF-Token", token)
//		// This is useful if you're sending JSON to clients or a front-end JavaScript
//		// framework.
//	}
//
func New(authKey []byte, opts ...Option) *Csrf {
		csr := parseOptions(opts...)

		// Set the defaults if no options have been specified
		if csr.opts.ErrorHandler == nil {
			csr.opts.ErrorHandler = http.HandlerFunc(unauthorizedHandler)
		}

		if csr.opts.MaxAge < 0 {
			// Default of 12 hours
			csr.opts.MaxAge = defaultAge
		}

		if csr.opts.FieldName == "" {
			csr.opts.FieldName = fieldName
		}

		if csr.opts.CookieName == "" {
			csr.opts.CookieName = cookieName
		}

		if csr.opts.RequestHeader == "" {
			csr.opts.RequestHeader = headerName
		}

		// Create an authenticated securecookie instance.
		if csr.sc == nil {
			csr.sc = securecookie.New(authKey, nil)
			// Use JSON serialization (faster than one-off gob encoding)
			csr.sc.SetSerializer(securecookie.JSONEncoder{})
			// Set the MaxAge of the underlying securecookie.
			csr.sc.MaxAge(csr.opts.MaxAge)
		}

		if csr.st == nil {
			// Default to the cookieStore
			csr.st = &cookieStore{
				name:     csr.opts.CookieName,
				maxAge:   csr.opts.MaxAge,
				secure:   csr.opts.Secure,
				httpOnly: csr.opts.HttpOnly,
				sameSite: csr.opts.SameSite,
				path:     csr.opts.Path,
				domain:   csr.opts.Domain,
				sc:       csr.sc,
			}
		}
		
		return csr
}

// Implements http.Handler for the csrf type.
func (csr *Csrf) Protect() gin.HandlerFunc {
	return func(c *gin.Context) {
		r := c.Request
		w := c.Writer

		// Skip the check if directed to. This should always be a bool.
		if val, err := contextGet(r, skipCheckKey); err == nil {
			if skip, ok := val.(bool); ok {
				if skip {
					c.Next()
					return
				}
			}
		}

		// Retrieve the token from the session.
		// An error represents either a cookie that failed HMAC validation
		// or that doesn't exist.
		realToken, err := csr.st.Get(r)
		if err != nil || len(realToken) != tokenLength {
			// If there was an error retrieving the token, the token doesn't exist
			// yet, or it's the wrong length, generate a new token.
			// Note that the new token will (correctly) fail validation downstream
			// as it will no longer match the request token.
			realToken, err = generateRandomBytes(tokenLength)
			if err != nil {
				r = envError(r, err)
				c.AbortWithStatus(http.StatusForbidden)
				return
			}

			// Save the new (real) token in the session store.
			err = csr.st.Save(realToken, w)
			if err != nil {
				r = envError(r, err)
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
		}

		// Save the masked token to the request context
		c.Set(tokenKey, mask(realToken, r))
		// Save the field name to the request context
		c.Set(formKey, csr.opts.FieldName)

		// HTTP methods not defined as idempotent ("safe") under RFC7231 require
		// inspection.
		if !contains(safeMethods, r.Method) {
			// Enforce an origin check for HTTPS connections. As per the Django CSRF
			// implementation (https://goo.gl/vKA7GE) the Referer header is almost
			// always present for same-domain HTTP requests.
			if r.URL.Scheme == "https" {
				// Fetch the Referer value. Call the error handler if it's empty or
				// otherwise fails to parse.
				referer, err := url.Parse(r.Referer())
				if err != nil || referer.String() == "" {
					r = envError(r, ErrNoReferer)
					csr.opts.ErrorHandler.ServeHTTP(w, r)
					return
				}

				valid := sameOrigin(r.URL, referer)

				if !valid {
					for _, trustedOrigin := range csr.opts.TrustedOrigins {
						if referer.Host == trustedOrigin {
							valid = true
							break
						}
					}
				}

				if valid == false {
					r = envError(r, ErrBadReferer)
					c.AbortWithStatus(http.StatusForbidden)
					return
				}
			}

			// If the token returned from the session store is nil for non-idempotent
			// ("unsafe") methods, call the error handler.
			if realToken == nil {
				r = envError(r, ErrNoToken)
				c.AbortWithStatus(http.StatusForbidden)
				return
			}

			// Retrieve the combined token (pad + masked) token and unmask it.
			requestToken := unmask(csr.requestToken(r))

			// if the request token is a trusted one we don't check against the real token
			if len(csr.opts.TrustedTokens) > 0 {
				for _, trustedToken := range csr.opts.TrustedTokens {
					// Decode the "issued" (pad + masked) token sent in the request. Return a
					// nil byte slice on a decoding error (this will fail upstream).
					decoded, err := base64.StdEncoding.DecodeString(trustedToken)
					if err != nil {
						continue
					}

					if len(unmask(decoded)) == len(requestToken) {
						return
					}
				}
			}

			// Compare the request token against the real token
			if !compareTokens(requestToken, realToken) {
				r = envError(r, ErrBadToken)
				c.AbortWithStatus(http.StatusForbidden)
				return
			}

		}

		// Set the Vary: Cookie header to protect clients from caching the response.
		w.Header().Add("Vary", "Cookie")

		// Clear the request context after the handler has completed.
		//contextClear(r)
		
		c.Next()
	}
}

// unauthorizedhandler sets a HTTP 403 Forbidden status and writes the
// CSRF failure reason to the response.
func unauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, fmt.Sprintf("%s - %s",
		http.StatusText(http.StatusForbidden), FailureReason(r)),
		http.StatusForbidden)
	return
}

func GetTokenKey() string {
	return tokenKey
}
