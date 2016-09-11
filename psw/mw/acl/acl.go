package acl

import (
	"log"
	"net/http"
	"strings"

	"github.com/LeKovr/elsa-auth/psw/struct/token"
	"github.com/LeKovr/elsa/mw/flow"
)

// -----------------------------------------------------------------------------

// Middleware is a struct that has a ServeHTTP method
type Middleware struct {
	Log    *log.Logger
	Field  string
	Prefix string
	Roles  []string
}

// -----------------------------------------------------------------------------

func New(logger *log.Logger, field, prefix string, roles ...string) *Middleware {
	return &Middleware{Log: logger, Prefix: prefix, Field: field, Roles: roles}
}

// -----------------------------------------------------------------------------

// ServeHTTP is the middleware handler
func (mw *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	url := r.URL.RequestURI()
	inGame := strings.HasPrefix(url, mw.Prefix)

	if inGame {
		mw.Log.Printf("debug: Check roles: %s", mw.Roles)
		ctx := r.Context()
		d := ctx.Value(mw.Field)
		if d == nil || d.(*token.Record) == nil || !slicesHasCommon(d.(*token.Record).Roles, mw.Roles) {
			// 403
			mw.Log.Printf("warn: Check roles %s for %s failed", mw.Roles, url)
			flow.Prohibit(r)
		}
	}
	next(w, r)
}

func slicesHasCommon(original, target []string) bool {
	for _, i := range original {
		for _, x := range target {
			if i == x {
				return true
			}
		}
	}
	return false
}
