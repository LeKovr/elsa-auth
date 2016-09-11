package user

import (
	"log"
	"net/http"

	rpc "github.com/gorilla/rpc/v2/json2"

	"github.com/LeKovr/elsa-auth/psw/struct/account"
	"github.com/LeKovr/elsa-auth/psw/struct/token"
	"github.com/LeKovr/elsa-auth/psw/utils"

	"github.com/LeKovr/go-base/database"
)

// -----------------------------------------------------------------------------

type Service struct {
	Log     *log.Logger
	DB      *database.DB
	Field   string // Context field for Sessiondata
	IPField string // `long:"logger_realip_field" default:"real-ip" description:"Context field for Real ip"`
}

// -----------------------------------------------------------------------------

func New(logger *log.Logger, db *database.DB, field, ipfield string) *Service {
	return &Service{Log: logger, DB: db, Field: field, IPField: ipfield}
}

// -----------------------------------------------------------------------------

// EmptyArgs - struct for empty args
type EmptyArgs struct {
}

// Profile - return current user's profile (from JWT)
func (srv *Service) Profile(r *http.Request, args *EmptyArgs, result *token.Record) error {

	me := utils.GetMe(r, srv.Field)
	*result = *me
	return nil
}

// -----------------------------------------------------------------------------

// UserSetPasswordArgs - аргументы метода UserSetPassword
type UserSetPasswordArgs struct {
	Password, Password2 string
}

// UserSetPassword - set new password
func (srv *Service) UserSetPassword(r *http.Request, args *UserSetPasswordArgs, result *int64) error {

	me := utils.GetMe(r, srv.Field)
	if me == nil {
		return &rpc.Error{Code: -32011, Message: "Auth required"}
	}

	if args.Password == "" {
		return &rpc.Error{Code: -32013, Message: "Empty password"}
	} else if args.Password != args.Password2 {
		return &rpc.Error{Code: -32013, Message: "Passwords does not match"}
	}

	p, err := utils.HashedPassword(args.Password)
	if err != nil {
		srv.Log.Printf("error: User password hash error: %+v", err)
		return &rpc.Error{Code: -32013, Message: "Method error"}
	}

	ip := utils.GetIP(r, srv.IPField)

	acc := account.Record{ID: me.ID}
	has, err := srv.DB.Engine.Get(&acc)
	if err != nil {
		return &rpc.Error{Code: -32014, Message: "Method error"}
	} else if !has {
		srv.Log.Printf("error: Unknown user (%+v) from ip %s", acc, ip)
		return &rpc.Error{Code: -32001, Message: "Login error"}

		// ToDo: } else if !acc.Enabled {

	}
	acc.Password = p
	if _, err = srv.DB.Engine.Id(me.ID).Cols("password").Update(&acc); err != nil {
		srv.Log.Printf("error: Password change error: %+v", err)
		return &rpc.Error{Code: -32014, Message: "Method error"}
	}
	srv.Log.Printf("debug: Change password for user ID %d from ip %s (%s / %s))", me.ID, ip, args.Password, p)
	*result = me.ID
	return nil
}
