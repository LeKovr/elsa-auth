package admin

import (
	"bytes"
	"log"
	"net/http"
	"strings"
	"text/template"

	rpc "github.com/gorilla/rpc/v2/json2"

	"github.com/LeKovr/elsa-auth/psw/struct/account"
	//	"github.com/LeKovr/elsa-auth/psw/struct/token"
	"github.com/LeKovr/elsa-auth/psw/utils"

	"github.com/LeKovr/go-base/database"
	"github.com/LeKovr/go-base/mailer"
)

// -----------------------------------------------------------------------------

// Service holds service attributes
type Service struct {
	Log      *log.Logger
	DB       *database.DB
	Template *template.Template
	Mailer   *mailer.App

	Field   string // Context field for Sessiondata
	IPField string // `long:"logger_realip_field" default:"real-ip" description:"Context field for Real ip"`
}

// -----------------------------------------------------------------------------

// Mailer sets mailer
func Mailer(m *mailer.App) func(srv *Service) error {
	return func(srv *Service) error {
		return srv.setMailer(m)
	}
}

// -----------------------------------------------------------------------------
// Internal setters

func (srv *Service) setMailer(m *mailer.App) error {
	srv.Mailer = m
	return nil
}

// -----------------------------------------------------------------------------

// New - Конструктор сервера API
func New(logger *log.Logger, db *database.DB, field, ipfield string, options ...func(srv *Service) error) (srv *Service, err error) {

	srv = &Service{Log: logger, DB: db, Field: field, IPField: ipfield}

	for _, option := range options {
		err := option(srv)
		if err != nil {
			return nil, err
		}
	}

	if srv.Mailer != nil {
		srv.Template, err = template.New("").ParseFiles("message.html.go") // TODO
		if err != nil {
			return nil, err
		}
	}
	//srv.initDB()
	return
}

// -----------------------------------------------------------------------------

// UserListArgs - аргументы метода UserList
type UserListArgs struct {
	Offset, By, Page int
	Email            string
}

// UserList - get user list
func (srv *Service) UserList(r *http.Request, args *UserListArgs, result *account.Records) error {

	if args.Page > 0 {
		args.Offset = args.Page * args.By
	}

	var recs account.Records
	err := srv.DB.Engine.
		Where("email like ?", "%"+args.Email+"%").
		Limit(args.By, args.Offset).
		Asc("email").
		Find(&recs)

	if err != nil {
		srv.Log.Printf("error: Fetch records error: %+v", err)
		return &rpc.Error{Code: -32012, Message: "Fetch error"}
	}

	// drop passwords
	for i := 0; i < len(recs); i++ {
		recs[i].Password = ""
	}
	srv.Log.Printf("debug: Rows=%d", len(recs))

	*result = recs
	return nil
}

// -----------------------------------------------------------------------------

// RowCount - количество строк в выборке
type RowCount int64

// UserListCount - выборка строк из журнала
func (srv *Service) UserListCount(r *http.Request, args *UserListArgs, result *RowCount) error {

	total, err := srv.DB.Engine.
		Where("email like ?", "%"+args.Email+"%").
		Count(&account.Record{})

	if err != nil {
		srv.Log.Printf("error: Fetch records error: %+v", err)
		return &rpc.Error{Code: -32012, Message: "Fetch error"}
	}

	srv.Log.Printf("debug: Count=%d", total)

	*result = RowCount(total)
	return nil
}

// -----------------------------------------------------------------------------

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

// UserSaveArgs - аргументы метода UserSave
type UserSaveArgs struct {
	ID                              int64
	Notify, Disabled                bool // send email to user
	Login, Name, Email, Group, Data string
}

// UserSave - add new user
func (srv *Service) UserSave(r *http.Request, args *UserSaveArgs, result *int64) error {
	me := utils.GetMe(r, srv.Field)

	if strings.Count(args.Email, "@") != 1 {
		return &rpc.Error{Code: -32012, Message: "Incorrect email"}
	}

	// TODO: no disable/remove myself
	srv.Log.Printf("debug: Save user: %+v", args)

	acc := account.Record{Login: args.Email, Email: args.Email, Name: args.Name, Disabled: args.Disabled, Data: args.Data}
	if args.Name == "" {
		acc.Name = args.Email
	}
	var op string
	var err error
	if args.ID != me.ID {
		acc.Group = args.Group // change group only to others
	}
	if args.ID == 0 {
		_, err = srv.DB.Engine.Insert(&acc)
		op = "create"
	} else {
		// user exists?
		var acc0 account.Record
		has, err := srv.DB.Engine.Id(args.ID).Cols("version").Get(&acc0)
		if !has {
			srv.Log.Printf("info: Unknown user ID (%d)", args.ID)
			return &rpc.Error{Code: -32001, Message: "Save error"}
		} else if err != nil {
			srv.Log.Printf("warn: User (%+v) fetch error: %+v", acc, err)
			return &rpc.Error{Code: -32002, Message: "Save error"}
		}
		acc.Version = acc0.Version
		_, err = srv.DB.Engine.Id(args.ID).Cols("login", "email", "name", "disabled", "data").Update(&acc)
		op = "edit"
	}
	if err != nil {
		srv.Log.Printf("error: User save error: %+v", err)
		return &rpc.Error{Code: -32010, Message: "Method error"}
	}

	*result = acc.ID

	if args.Notify {
		if srv.Mailer == nil {
			srv.Log.Print("warn: Notify requested but mailer not set")
			return nil
		}
		// prepare mail
		vars := &TemplateVars{
			User:   acc,
			Meta:   map[string]string{},
			Scheme: r.Header.Get("X-Forwarded-Proto"),
			Host:   r.Host, //r.Header.Get("Host"),
			Data:   op,
		}

		buf := new(bytes.Buffer)
		err = srv.Template.ExecuteTemplate(buf, "sendInfo", &vars)
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

	}

	return nil
}
