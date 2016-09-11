package jwt

import (
	"context"
	"log"
	"net/http"
	"net/url"

	"github.com/LeKovr/elsa-auth/psw/struct/token"
	"github.com/LeKovr/go-base/jwtutil"
)

const (
	// Bearer is a prefix of JWT header value
	Bearer = "Bearer"
)

// -----------------------------------------------------------------------------

// Flags is a package flags sample
// in form ready for use with github.com/jessevdk/go-flags
type Flags struct {
	AuthHeader string `long:"auth_token_header" default:"X-Elfire-Token" description:"Header field to store auth token"`
	AuthCookie string `long:"auth_token_cookie" default:"elfire_sso_token" description:"Cookie name to store auth token"`
	//  UIDHeader  string `long:"uid_header" default:"X-Elfire-UID" description:"Header field to store user ID"`
	//  GIDHeader  string `long:"gid_header" default:"X-Elfire-GID" description:"Header field to store group ID"`
}

// Middleware is a struct that has a ServeHTTP method
type Middleware struct {
	Log    *log.Logger
	Config *Flags
	Token  *jwtutil.App
	Field  string // Context field for Profile data
}

// -----------------------------------------------------------------------------

func New(logger *log.Logger, cfg *Flags, token *jwtutil.App, field string) *Middleware {
	return &Middleware{Log: logger, Config: cfg, Token: token, Field: field}
}

// -----------------------------------------------------------------------------

// ServeHTTP is the middleware handler
func (mw *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	l := len(Bearer)
	header := r.Header.Get(mw.Config.AuthHeader)
	var key string

	if header == "" && mw.Config.AuthCookie != "" {
		c, _ := r.Cookie(mw.Config.AuthCookie) // TODO: err
		if c != nil {
			mw.Log.Printf("trace: Got cookie (%+v)", c)
			key, _ = url.QueryUnescape(c.Value) // TODO: err
		}
	} else if len(header) > l+1 && header[:l] == Bearer {
		key = header[l+1:]
	}

	if key != "" {
		mw.Log.Printf("trace: JWT (%s)", key)

		ret := new(token.Attr)
		if err := mw.Token.Cryptor.Decode("appKey", key, ret); err != nil {
			mw.Log.Printf("warn: JWT (%s) encode error: %+v", key, err)
		} else {
			mw.Log.Printf("debug: Key decoded (%+v)", *ret)
			// TODO: check expire
			p := ret.Record
			ctx := r.Context()
			ctx = context.WithValue(ctx, mw.Field, &p)
			r = r.WithContext(ctx)
		}
	}
	next(w, r)
}
