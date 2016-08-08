package psw

import (
	"bytes"
	json "github.com/gorilla/rpc/v2/json2"
	"net/http"
	"strings"

	"github.com/LeKovr/go-base/mailer"
)

// Mailer sets mailer
func Mailer(m *mailer.App) func(a *App) error {
	return func(a *App) error {
		return a.setMailer(m)
	}
}

// -----------------------------------------------------------------------------
// Internal setters

func (a *App) setMailer(m *mailer.App) error {
	a.Mailer = m
	return nil
}

// -----------------------------------------------------------------------------

// UserListArgs - аргументы метода UserList
type UserListArgs struct {
	Offset, By, Page int
	Email            string
}

// UserList - get user list
func (a *App) UserList(r *http.Request, args *UserListArgs, reply *Accounts) error {
	me, err := a.ParseJWT(r)
	if err != nil {
		a.Log.Warningf("JWT parse error: %+v", err)
		return &json.Error{Code: -32011, Message: "Auth required"}
	}
	if me.Group != a.Config.AdminGroup {
		a.Log.Warningf("Group %s does not match %s", me.Group, a.Config.AdminGroup)
		return &json.Error{Code: -32012, Message: "Not enough perms"}
	}
	if args.Page > 0 {
		args.Offset = args.Page * args.By
	}

	var recs Accounts
	err = a.DB.Engine.
		Where("email like ?", "%"+args.Email+"%").
		Limit(args.By, args.Offset).
		Asc("email").
		Find(&recs)

	if err != nil {
		a.Log.Errorf("Fetch records error: %+v", err)
		return &json.Error{Code: -32012, Message: "Fetch error"}
	}

	// drop passwords
	for i := 0; i < len(recs); i++ {
		recs[i].Password = ""
	}
	a.Log.Debugf("Rows=%d", len(recs))

	*reply = recs
	return nil
}

// -----------------------------------------------------------------------------

// RowCount - количество строк в выборке
type RowCount int64

// UserListCount - выборка строк из журнала
func (a *App) UserListCount(r *http.Request, args *UserListArgs, reply *RowCount) error {
	me, err := a.ParseJWT(r)
	if err != nil {
		a.Log.Errorf("JWT parse error: %+v", err)
		return &json.Error{Code: -32011, Message: "Auth required"}
	}
	if me.Group != a.Config.AdminGroup {
		a.Log.Warningf("Group %s does not match %s", me.Group, a.Config.AdminGroup)
		return &json.Error{Code: -32012, Message: "Not enough perms"}
	}
	if args.Page > 0 {
		args.Offset = args.Page * args.By
	}

	total, err := a.DB.Engine.
		Where("email like ?", "%"+args.Email+"%").
		Limit(args.By, args.Offset).
		Asc("group", "email").
		Count(&Account{})

	if err != nil {
		a.Log.Errorf("Fetch records error: %+v", err)
		return &json.Error{Code: -32012, Message: "Fetch error"}
	}

	a.Log.Debugf("Count=%d", total)
	*reply = RowCount(total)
	return nil
}

// -----------------------------------------------------------------------------

// UserSaveArgs - аргументы метода UserSave
type UserSaveArgs struct {
	ID                              int64
	Notify, Disabled                bool // send email to user
	Login, Name, Email, Group, Data string
}

// UserSave - add new user
func (a *App) UserSave(r *http.Request, args *UserSaveArgs, reply *int64) error {
	me, err := a.ParseJWT(r)
	if err != nil {
		a.Log.Warningf("JWT parse error: %+v", err)
		return &json.Error{Code: -32011, Message: "Auth required"}
	}
	if me.Group != a.Config.AdminGroup {
		a.Log.Warningf("Group %s does not match %s", me.Group, a.Config.AdminGroup)
		return &json.Error{Code: -32012, Message: "Not enough perms"}
	} else if strings.Count(args.Email, "@") != 1 {
		return &json.Error{Code: -32012, Message: "Incorrect email"}
	}

	// TODO: no disable/remove myself
	a.Log.Debugf("Save user: %+v", args)

	acc := Account{Login: args.Email, Email: args.Email, Name: args.Name, Disabled: args.Disabled, Data: args.Data}
	if args.Name == "" {
		acc.Name = args.Email
	}
	var op string
	if args.ID != me.ID {
		acc.Group = args.Group // change group only to others
	}
	if args.ID == 0 {
		_, err = a.DB.Engine.Insert(&acc)
		op = "create"
	} else {
		// user exists?
		var acc0 Account
		has, err := a.DB.Engine.Id(args.ID).Cols("version").Get(&acc0)
		if !has {
			a.Log.Infof("Unknown user ID (%d)", args.ID)
			return &json.Error{Code: -32001, Message: "Save error"}
		} else if err != nil {
			a.Log.Warningf("User (%+v) fetch error: %+v", acc, err)
			return &json.Error{Code: -32002, Message: "Save error"}
		}
		acc.Version = acc0.Version
		_, err = a.DB.Engine.Id(args.ID).Update(&acc)
		op = "edit"
	}
	if err != nil {
		a.Log.Errorf("User save error: %+v", err)
		return &json.Error{Code: -32010, Message: "Method error"}
	}

	if args.Notify {
		// prepare mail
		vars := &TemplateVars{
			User:   acc,
			Meta:   map[string]string{},
			Scheme: r.Header.Get("X-Forwarded-Proto"),
			Host:   r.Host, //r.Header.Get("Host"),
			Data:   op,
		}

		buf := new(bytes.Buffer)
		err = a.Template.ExecuteTemplate(buf, "sendInfo", &vars)
		if err != nil {
			a.Log.Errorf("Mail prep error: %s", err)
			return &json.Error{Code: -32103, Message: "Mail prepare error"}
		}

		// send email
		err = a.Mailer.Send(acc.Email, acc.Name, vars.Meta["subject"], buf.String(), []string{})
		if err != nil {
			a.Log.Errorf("Mail send error: %s", err)
			return &json.Error{Code: -32104, Message: "Mail send error"}
		}

	}

	*reply = acc.ID
	return nil
}

// TemplateVars holds template variables
type TemplateVars struct {
	User         Account
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
func (a *App) UserSendToken(r *http.Request, args *UserSendTokenArgs, reply *int64) error {

	if args.Email == "" {
		return &json.Error{Code: -32014, Message: "No email given"}
	}
	if a.Mailer == nil {
		return &json.Error{Code: -32015, Message: "Sending disabled"}
	}
	ip := r.Header.Get("Client-Ip")
	acc := Account{Email: args.Email}
	has, err := a.DB.Engine.Get(&acc)

	if err != nil {
		return &json.Error{Code: -32014, Message: "Method error"}

	} else if !has {
		a.Log.Infof("Unknown user (%+v) from ip %s", acc, ip)
		return &json.Error{Code: -32001, Message: "Login error"}

		// ToDo: } else if !acc.Enabled {

	}

	jwt, err := a.genJWT(acc)
	if err != nil {
		return &json.Error{Code: -32004, Message: "Login error"}
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
	err = a.Template.ExecuteTemplate(buf, "sendToken", vars)

	a.Log.Infof("Template data: %+v (%+v)", vars, r)

	if err != nil {
		a.Log.Errorf("Mail prep error: %s", err)
		return &json.Error{Code: -32103, Message: "Mail prepare error"}
	}

	// send email
	err = a.Mailer.Send(acc.Email, acc.Name, vars.Meta["subject"], buf.String(), []string{})
	if err != nil {
		a.Log.Errorf("Mail send error: %s", err)
		return &json.Error{Code: -32104, Message: "Mail send error"}
	}
	return nil
}

// -----------------------------------------------------------------------------

// UserSetPasswordArgs - аргументы метода UserSetPassword
type UserSetPasswordArgs struct {
	Password, Password2 string
}

// UserSetPassword - set new password
func (a *App) UserSetPassword(r *http.Request, args *UserSetPasswordArgs, reply *int64) error {
	me, err := a.ParseJWT(r)
	if err != nil {
		a.Log.Warningf("JWT parse error: %+v", err)
		return &json.Error{Code: -32011, Message: "Auth required"}
	}

	if args.Password == "" {
		return &json.Error{Code: -32013, Message: "Empty password"}
	} else if args.Password != args.Password2 {
		return &json.Error{Code: -32013, Message: "Passwords does not match"}
	}

	p, err := hashedPassword(args.Password)
	if err != nil {
		a.Log.Errorf("User password hash error: %+v", err)
		return &json.Error{Code: -32013, Message: "Method error"}
	}
	ip := r.Header.Get("Client-Ip")

	acc := Account{ID: me.ID}
	has, err := a.DB.Engine.Get(&acc)
	if err != nil {
		return &json.Error{Code: -32014, Message: "Method error"}
	} else if !has {
		a.Log.Errorf("Unknown user (%+v) from ip %s", acc, ip)
		return &json.Error{Code: -32001, Message: "Login error"}

		// ToDo: } else if !acc.Enabled {

	}
	acc.Password = p
	if _, err = a.DB.Engine.Update(&acc); err != nil {
		a.Log.Errorf("Password change error: %+v", err)
		return &json.Error{Code: -32014, Message: "Method error"}
	}
	a.Log.Debugf("Change password for user ID %d from ip %s (%s / %s))", me.ID, ip, args.Password, p)
	*reply = me.ID
	return nil
}
