// anon holds anonymous functions
package anon

import (
	"bytes"
	"log"
	"net/http"
	"strings"
	"text/template"
	"time"

	rpc "github.com/gorilla/rpc/v2/json2"

	"github.com/LeKovr/elsa-auth/psw/struct/account"
	"github.com/LeKovr/elsa-auth/psw/struct/token"
	"github.com/LeKovr/elsa-auth/psw/utils"

	"github.com/LeKovr/go-base/database"
	"github.com/LeKovr/go-base/jwtutil"
	"github.com/LeKovr/go-base/mailer"
)

const (
	// Bearer is a prefix of JWT header value
	Bearer = "Bearer"
)

// -----------------------------------------------------------------------------

// Flags is a package flags sample
// in form ready for use with github.com/jessevdk/go-flags
type Flags struct {
	FailDelay int `long:"psw_delay" default:"5" description:"Delay response when password wrong (seconds)"`

	AdminGroup string `long:"adm_group" default:"admin" description:"Admin user group"`
	AdminEmail string `long:"adm_email"  default:"ak@elfire.ru" description:"Admin user email"`
	AdminPass  string `long:"adm_pass"  description:"Admin user password (Default: set random & log)"`
	Template   string `long:"psw_template"  default:"messages.gohtml" description:"Mail templates file"`
}

// -----------------------------------------------------------------------------

// Service holds service attributes
type Service struct {
	Log      *log.Logger
	Config   *Flags
	DB       *database.DB
	Token    *jwtutil.App
	Template *template.Template
	Mailer   *mailer.App

	IPField string // `long:"logger_realip_field" default:"real-ip" description:"Context field for Real ip"`
}

// -----------------------------------------------------------------------------

// Mailer sets mailer
func Mailer(m *mailer.App) func(srv *Service) error {
	return func(srv *Service) error {
		return srv.setMailer(m)
	}
}

// Token sets cryptor object
func Token(t *jwtutil.App) func(srv *Service) error {
	return func(srv *Service) error {
		return srv.setToken(t)
	}
}

// -----------------------------------------------------------------------------
// Internal setters

func (srv *Service) setMailer(m *mailer.App) error {
	srv.Mailer = m
	return nil
}

func (srv *Service) setToken(t *jwtutil.App) error {
	srv.Token = t
	return nil
}

// -----------------------------------------------------------------------------

// New - Конструктор сервера API
func New(logger *log.Logger, cfg *Flags, db *database.DB, field string, options ...func(srv *Service) error) (srv *Service, err error) {

	srv = &Service{Log: logger, Config: cfg, DB: db, IPField: field}

	for _, option := range options {
		err := option(srv)
		if err != nil {
			return nil, err
		}
	}

	if srv.Mailer != nil {
		srv.Template, err = template.New("").ParseFiles(srv.Config.Template)
		if err != nil {
			return nil, err
		}
	}
	srv.initDB()
	return
}

// -----------------------------------------------------------------------------

// LoginArgs - аргументы метода Login
type LoginArgs struct {
	Login, Email, Password string
}

// LoginResp - результат метода Login
type LoginResult struct {
	JWT string
}

// -----------------------------------------------------------------------------

// Login - авторизация пользователя
func (srv *Service) Login(r *http.Request, args *LoginArgs, result *LoginResult) error {

	ip := utils.GetIP(r, srv.IPField)
	var acc = account.Record{}
	if args.Email != "" {
		acc.Email = args.Email
	} else if args.Login != "" {
		acc.Login = args.Login
	} else {
		return &rpc.Error{Code: -32001, Message: "Login ID required"}
	}

	has, err := srv.DB.Engine.Get(&acc)

	if !has {
		srv.Log.Printf("info: Unknown user (%+v) from ip %s", args, ip)
		return &rpc.Error{Code: -32001, Message: "Login error"}
	} else if err != nil {
		srv.Log.Printf("warn: User (%+v) from ip %s fetch error: %+v", acc, ip, err)
		return &rpc.Error{Code: -32002, Message: "Login error"}
	} else {
		err = utils.CheckPassword(acc.Password, args.Password)
		if err != nil {
			srv.Log.Printf("info: User with wrong pass: %+v", args)
			time.Sleep(time.Second * time.Duration(srv.Config.FailDelay)) // задержка от подбора
			return &rpc.Error{Code: -32003, Message: "Login error"}
		} else if acc.Disabled {
			return &rpc.Error{Code: -32011, Message: "User is disabled"}
		}
	}

	srv.Log.Printf("debug: User (%s) confirmed for ip %s", args.Email, ip)

	var jwt string
	jwt, err = srv.genJWT(&acc)
	if err != nil {
		return &rpc.Error{Code: -32004, Message: "Login error"}
	}

	result.JWT = jwt
	return nil

	//reply.Message = "Hello, " + args.Who + ", from " + srv.Data + "!"
}

// TemplateVars holds template variables
type TemplateVars struct {
	User         account.Record
	Scheme, Host string
	Meta         map[string]string
	Data         interface{}
}

// SetMeta used inside templates for metadata setting (like setting email subject)
func (tv *TemplateVars) SetMeta(key string, values ...string) string {
	val := strings.Join(values, "")
	tv.Meta[key] = val
	return ""
}

// -----------------------------------------------------------------------------

// UserSendTokenArgs - аргументы метода UserSendToken
type UserSendTokenArgs struct {
	Email string
}

// UserSendToken - add token by email
func (srv *Service) UserSendToken(r *http.Request, args *UserSendTokenArgs, result *int64) error {

	if args.Email == "" {
		return &rpc.Error{Code: -32014, Message: "No email given"}
	}
	if srv.Mailer == nil {
		return &rpc.Error{Code: -32015, Message: "Sending disabled"}
	}
	ip := utils.GetIP(r, srv.IPField)

	acc := account.Record{Email: args.Email}
	has, err := srv.DB.Engine.Get(&acc)

	if err != nil {
		return &rpc.Error{Code: -32014, Message: "Method error"}

	} else if !has {
		srv.Log.Printf("info: Unknown user (%+v) from ip %s", acc, ip)
		return &rpc.Error{Code: -32001, Message: "Login error"}

		// ToDo: } else if !acc.Enabled {

	}

	jwt, err := srv.genJWT(&acc)
	if err != nil {
		return &rpc.Error{Code: -32004, Message: "Login error"}
	}

	// prepare mail
	vars := &TemplateVars{
		User:   acc,
		Meta:   map[string]string{},
		Scheme: r.Header.Get("X-Forwarded-Proto"),
		Host:   r.Host, //r.Header.Get("Host"),
		Data:   jwt,
	}
	buf := new(bytes.Buffer)
	err = srv.Template.ExecuteTemplate(buf, "sendToken", vars)

	srv.Log.Printf("info: Template data: %+v (%+v)", vars, r)

	if err != nil {
		srv.Log.Printf("error: Mail prep error: %s", err)
		return &rpc.Error{Code: -32103, Message: "Mail prepare error"}
	}

	// send email
	err = srv.Mailer.Send(acc.Email, acc.Name, vars.Meta["subject"], buf.String(), []string{})
	if err != nil {
		srv.Log.Printf("error: Mail send error: %s", err)
		return &rpc.Error{Code: -32104, Message: "Mail send error"}
	}
	return nil
}

// -----------------------------------------------------------------------------

// generate jwt
func (srv *Service) genJWT(acc *account.Record) (string, error) {
	value := token.Attr{Record: token.Record{Name: acc.Name, Roles: []string{acc.Group}, ID: acc.ID}, Stamp: time.Now()}
	srv.Log.Printf("debug: Store %+v", value)
	encoded, err := srv.Token.Cryptor.Encode("appKey", value)
	if err == nil {
		srv.Log.Printf("debug: Set appKey %+v", encoded)
		return encoded, nil
	}
	srv.Log.Printf("warn: appKey encode error: %+v", err)
	return "", err
}

// -----------------------------------------------------------------------------

func (srv *Service) initDB() (err error) {

	engine := srv.DB.Engine

	// TODO: SELECT name FROM sqlite_master WHERE type='table' and name = ?

	acc := new(account.Record)
	err = engine.Sync(acc)
	if err != nil {
		srv.Log.Printf("fatal: DB sync error: %v", err)
	}

	isempty, err := engine.IsTableEmpty(acc) //"account")
	if err != nil {
		srv.Log.Printf("fatal: DB checkempty error: %v", err)
	}

	if isempty {
		pass := srv.Config.AdminPass
		if pass == "" {
			pass = utils.RandomString(8)
			srv.Log.Printf("warn: Initialize user %s with random pass %s", srv.Config.AdminEmail, pass)
		}
		var p string
		p, err = utils.HashedPassword(pass)
		if err != nil {
			srv.Log.Printf("error: User password hash error: %+v", err)
			return
		}
		acc := account.Record{Login: srv.Config.AdminEmail, Name: "admin", Email: srv.Config.AdminEmail, Password: p, Group: srv.Config.AdminGroup}
		if _, err = engine.Insert(&acc); err != nil {
			srv.Log.Printf("error: User add error: %+v", err)
			return
		}
	}

	return
}
