// Package psw is an API service for password authentication
package psw

import (
	"errors"
	json "github.com/gorilla/rpc/v2/json2"
	"github.com/gorilla/securecookie"
	"net/http"
	"text/template"
	"time"

	"github.com/LeKovr/go-base/database"
	"github.com/LeKovr/go-base/logger"
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
	AppKey    string `long:"psw_session_key" description:"Key to encode user session (default: random key reset on restart)"`
	BlockKey  string `long:"psw_block_key" default:"T<8rYvXmgLBdND(YW}3QRcLwh4$4P5eq" description:"Key to encode session blocks (16,32 or 62 byte)"`
	FailDelay int    `long:"psw_delay" default:"5" description:"Delay response when password wrong (seconds)"`

	AuthHeader string `long:"auth_token_header" default:"X-Elfire-Token" description:"Header field to store auth token"`
	UIDHeader  string `long:"uid_header" default:"X-Elfire-UID" description:"Header field to store user ID"`
	GIDHeader  string `long:"gid_header" default:"X-Elfire-GID" description:"Header field to store group ID"`

	AdminGroup string `long:"adm_group" default:"admin" description:"Admin user group"`
	AdminEmail string `long:"adm_email"  default:"ak@elfire.ru" description:"Admin user email"`
	AdminPass  string `long:"adm_pass"  description:"Admin user password (Default: set random & log)"`
	Template   string `long:"psw_template"  default:"messages.gohtml" description:"Mail templates file"`
}

// -----------------------------------------------------------------------------

// Profile - структура профиля
type Profile struct {
	ID          int64  // User ID
	Name, Group string // User Name and Group
}

// Cookie - структура, которая хранится в JWT
type Cookie struct {
	Profile
	Stamp time.Time
}

// -----------------------------------------------------------------------------

// Account is a user account table
type Account struct {
	ID       int64  `xorm:"'id' pk autoincr"`
	Login    string `xorm:"not null unique"`
	Group    string
	Name     string
	Password string
	Email    string `xorm:"not null unique"`
	Phone    string
	Data     string // some account related data
	Disabled bool   `xorm:"not null default 0"`
	Version  int    `xorm:"version"` // Optimistic Locking
}

// Accounts is an Account slice
type Accounts []Account

// -----------------------------------------------------------------------------

// App - Класс сервера API
type App struct {
	Cryptor  *securecookie.SecureCookie
	DB       *database.DB
	Template *template.Template
	Log      *logger.Log
	Mailer   *mailer.App
	Config   *Flags
}

// -----------------------------------------------------------------------------
// Functional options

// Config sets config struct
func Config(c *Flags) func(a *App) error {
	return func(a *App) error {
		return a.setConfig(c)
	}
}

// Cryptor sets securecookie generator
func Cryptor(a *App) error {
	return a.setCryptor()
}

// -----------------------------------------------------------------------------
// Internal setters

func (a *App) setConfig(c *Flags) error {
	a.Config = c
	return nil
}

func (a *App) setCryptor() error {

	var hashKeyBytes = []byte(a.Config.AppKey)
	if a.Config.AppKey == "" {
		hashKeyBytes = securecookie.GenerateRandomKey(32)
		a.Log.Warning("Random key generated. Sessions will be expired on restart")
	}
	var blockKeyBytes = []byte(a.Config.BlockKey) // "txVzHcURYJrK]UQ:d/YDmx97*Adwb;/%")

	var s = securecookie.New(hashKeyBytes, blockKeyBytes)
	var sz securecookie.JSONEncoder
	s.SetSerializer(sz)
	a.Cryptor = s
	return nil
}

// -----------------------------------------------------------------------------

// New - Конструктор сервера API
func New(db *database.DB, log *logger.Log, options ...func(a *App) error) (a *App, err error) {

	a = &App{DB: db, Log: log.WithField("in", "auth-psw")}

	for _, option := range options {
		err := option(a)
		if err != nil {
			return nil, err
		}
	}
	if a.Cryptor == nil {
		a.setCryptor()
	}

	a.Template, err = template.New("").ParseFiles(a.Config.Template)
	if err != nil {
		return nil, err
	}

	a.initDB()
	return

}

// -----------------------------------------------------------------------------

// ServeHTTP - Хэндлер метода /auth
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	a.Log.Debugf("Got http request: %v", r)

	if me, err := a.ParseJWT(r); err == nil {
		w.Header().Set(a.Config.UIDHeader, me.Name)
		w.Header().Set(a.Config.GIDHeader, me.Group)
		w.WriteHeader(200)
	} else if r.Header.Get(a.Config.AuthHeader) == "" {
		a.Log.Debug("Got empty JWT header")
		http.Error(w, http.StatusText(401), 401)
	} else {
		a.Log.Warningf("JWT parse error: %+v", err)
		// Not authenticated user, show 401
		http.Error(w, http.StatusText(401), 401)
	}
}

// -----------------------------------------------------------------------------

// LoginArgs - аргументы метода Login
type LoginArgs struct {
	Login, Email, Password string
}

// LoginResp - результат метода Login
type LoginResp struct {
	JWT string
}

// -----------------------------------------------------------------------------

// Login - авторизация пользователя
func (a *App) Login(r *http.Request, args *LoginArgs, reply *LoginResp) error {
	ip := r.Header.Get("Client-Ip")

	var acc = Account{}
	if args.Email != "" {
		acc.Email = args.Email
	} else if args.Login != "" {
		acc.Login = args.Login
	} else {
		return &json.Error{Code: -32001, Message: "Login ID required"}
	}

	has, err := a.DB.Engine.Get(&acc)

	if !has {
		a.Log.Infof("Unknown user (%+v) from ip %s", acc, ip)
		return &json.Error{Code: -32001, Message: "Login error"}
	} else if err != nil {
		a.Log.Warningf("User (%+v) from ip %s fetch error: %+v", acc, ip, err)
		return &json.Error{Code: -32002, Message: "Login error"}
	} else {
		err = checkPassword(acc.Password, args.Password)
		if err != nil {
			a.Log.Infof("User with wrong pass: %+v", args)
			time.Sleep(time.Second * time.Duration(a.Config.FailDelay)) // задержка от подбора

			return &json.Error{Code: -32003, Message: "Login error"}
		}
	}

	a.Log.Debugf("User (%s) confirmed for ip %s", args.Email, ip)

	if jwt, err := a.genJWT(acc); err == nil {
		reply.JWT = jwt
		return nil
	}

	return &json.Error{Code: -32004, Message: "Login error"}
}

// -----------------------------------------------------------------------------

// EmptyArgs - struct for empty args
type EmptyArgs struct {
}

// Profile - return current user's profile (from JWT)
func (a *App) Profile(r *http.Request, args *EmptyArgs, reply *Cookie) error {
	me, err := a.ParseJWT(r)
	if err != nil {
		return &json.Error{Code: -32011, Message: "Auth required"}
	}
	*reply = *me
	return nil
}

// -----------------------------------------------------------------------------

// ParseJWT - Расшифровать ключ (TODO: проверить его валидность )
func (a *App) ParseJWT(r *http.Request) (ret *Cookie, err error) {

	auth := r.Header.Get(a.Config.AuthHeader)
	l := len(Bearer)
	if len(auth) > l+1 && auth[:l] == Bearer {
		key := auth[l+1:]
		ret = new(Cookie)
		if err = a.Cryptor.Decode("appKey", key, ret); err == nil {
			a.Log.Debugf("Key decoded (%+v)", *ret)
		}
	} else {
		err = errors.New("Token required")
	}
	// TODO: check expire
	return
}

// -----------------------------------------------------------------------------

// generate jwt
func (a *App) genJWT(acc Account) (string, error) {
	value := Cookie{Profile: Profile{Name: acc.Name, Group: acc.Group, ID: acc.ID}, Stamp: time.Now()}
	a.Log.Debugf("Store %+v", value)
	encoded, err := a.Cryptor.Encode("appKey", value)
	if err == nil {
		a.Log.Debugf("Set appKey %+v", encoded)
		return encoded, nil
	}
	a.Log.Warningf("appKey encode error: %+v", err)
	return "", err
}

// -----------------------------------------------------------------------------

func (a *App) initDB() (err error) {

	engine := a.DB.Engine

	// TODO: SELECT name FROM sqlite_master WHERE type='table' and name = ?

	err = engine.Sync(new(Account))
	if err != nil {
		a.Log.Fatalf("DB sync error: %v", err)
	}

	isempty, err := engine.IsTableEmpty("account")
	if err != nil {
		a.Log.Fatalf("DB checkempty error: %v", err)
	}

	if isempty {
		pass := a.Config.AdminPass
		if pass == "" {
			pass = RandomString(8)
			a.Log.Warningf("Initialize user %s with random pass %s", a.Config.AdminEmail, pass)
		}
		var p string
		p, err = hashedPassword(pass)
		if err != nil {
			a.Log.Errorf("User password hash error: %+v", err)
			return
		}
		acc := Account{Login: a.Config.AdminEmail, Name: "admin", Email: a.Config.AdminEmail, Password: p, Group: a.Config.AdminGroup}
		if _, err = engine.Insert(&acc); err != nil {
			a.Log.Errorf("User add error: %+v", err)
			return
		}
	}

	return
}
