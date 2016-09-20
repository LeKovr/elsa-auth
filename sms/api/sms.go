// Package sms is an API service for authentication via SMS
package sms

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"regexp"
	"time"

	rpc "github.com/gorilla/rpc/v2/json2"

	"github.com/LeKovr/elsa-auth/psw/struct/token"
	"github.com/LeKovr/elsa-auth/psw/utils"
	"github.com/LeKovr/go-base/jwtutil"
	"github.com/LeKovr/kvstore"
	"github.com/LeKovr/smpp"
)

var (
	phoneFilter *regexp.Regexp // Regexp compiled once
)

// -----------------------------------------------------------------------------

// Flags is a package flags sample
// in form ready for use with github.com/jessevdk/go-flags
type Flags struct {
	smpp.Flags
	AppKey    string `long:"sms_session_key" description:"Key to encode user session (default: random key reset on restart)"`
	BlockKey  string `long:"sms_block_key" default:"T<8rYvXmgLBdND(YW}3QRcLwh4$4P5eq" description:"Key to encode session blocks (16,32 or 62 byte)"`
	FailDelay int    `long:"sms_delay" default:"5" description:"Delay response when password wrong (seconds)"`
	SmsRetry  int    `long:"sms_retry" default:"300" description:"Repeat SMS only after this period (seconds)"`
	StoreName string `long:"sms_code_file" default:"store.json" description:"File to store active sent codes at program exit"`
}

// -----------------------------------------------------------------------------
// kvstore definition

type PhoneData struct {
	Phone string    `json:"phone"`
	Code  string    `json:"code"`
	Stamp time.Time `json:"stamp"`
}

func (pd PhoneData) Init() (kvstore.StoreData, error) {
	pd.Stamp = time.Now() // TODO if add_stamp
	return pd, nil
}

func (pd PhoneData) Fetch(buf []byte) (kvstore.StoreData, error) {
	v := PhoneData{}
	err := json.Unmarshal(buf, &v)
	return v, err
}

// -----------------------------------------------------------------------------

func init() {
	phoneFilter, _ = regexp.Compile("[^0-9]")
}

type ArgsKey struct {
	Key string
}
type Resp struct {
	Code                    int
	Data, Phone, IP, Status string
}

type Cookie struct {
	Phone string
	Stamp time.Time
}

// HookFunc вызывается при успехе проверки телефона
type HookFunc func(ip, phone, repeat string) string

// Service holds service attributes
type Service struct {
	Store   *kvstore.Store
	Hook    *HookFunc
	Log     *log.Logger
	Config  *Flags
	Token   *jwtutil.App
	IPField string // Context field for Real ip
}

// -----------------------------------------------------------------------------
// Functional options

// Config sets config struct
func Config(c *Flags) func(srv *Service) error {
	return func(srv *Service) error {
		return srv.setConfig(c)
	}
}

// Hook sets onSuccess hook func
func Hook(f HookFunc) func(srv *Service) error {
	return func(srv *Service) error {
		return srv.setHook(&f)
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

func (srv *Service) setConfig(c *Flags) error {
	srv.Config = c
	return nil
}

func (srv *Service) setHook(f *HookFunc) error {
	srv.Hook = f
	return nil
}

func (srv *Service) setToken(t *jwtutil.App) error {
	srv.Token = t
	return nil
}

// -----------------------------------------------------------------------------

// New - Class constructor
func New(logger *log.Logger, field string, options ...func(srv *Service) error) (*Service, error) {

	srv := Service{
		Log:     logger,
		IPField: field,
	}

	for _, option := range options {
		err := option(&srv)
		if err != nil {
			return nil, err
		}
	}
	srv.Store, _ = kvstore.New(new(PhoneData), logger, kvstore.Config(&kvstore.Flags{StoreName: srv.Config.StoreName}))
	return &srv, nil

}

// -----------------------------------------------------------------------------

// Init - если клиент уже авторизован вернуть Code=4, иначе - проверить остальные варианты
func (srv *Service) Init(r *http.Request, args *ArgsKey, reply *Resp) error {

	ip := utils.GetIP(r, srv.IPField)

	//  1. Если key передан, корректен и не просрочен => Активация + факт реюза пишем в логи
	if args.Key != "" {
		keyData, err := srv.parseKey(args.Key)
		if err == nil {
			*reply = Resp{Code: 4, Phone: keyData.Phone}
			return nil
		}
	}
	return srv.initCheck(ip, reply)
}

// -----------------------------------------------------------------------------

// InitForced - если клиент уже авторизован, выполнить активацию, иначе - проверить остальные варианты
func (srv *Service) InitForced(r *http.Request, args *ArgsKey, reply *Resp) error {

	ip := utils.GetIP(r, srv.IPField)

	//  1. Если key передан, корректен и не просрочен => Активация + факт реюза пишем в логи
	if args.Key != "" {
		keyData, err := srv.parseKey(args.Key)
		if err == nil {
			*reply, _ = srv.activate(ip, keyData.Phone, true)
			return nil
		}
	}
	return srv.initCheck(ip, reply)
}

// -----------------------------------------------------------------------------

// initCheck - выполнить начальные проверки
func (srv *Service) initCheck(ip string, reply *Resp) error {

	//  2. Проверить баланс (32001)  *cfgAppMinBalance*
	ok, err := smpp.IsBalanceOk(&srv.Config.Flags, srv.Log)
	if err != nil {
		return &rpc.Error{Code: -32001, Message: "Balance error: " + err.Error()}
	}
	if !ok {
		return &rpc.Error{Code: -32002, Message: "Balance exceeded"}
	}

	*reply = Resp{Code: 0, IP: ip}

	//  3. Проверить, не было ли за последние *cfgAppSmsRetrySec* отправки с этого ip и вернуть - сколько секунд до повтора
	data, ok := srv.Store.Get(ip)
	if ok {
		wait := data.(PhoneData).Stamp.Unix() + int64(srv.Config.SmsRetry) - time.Now().Unix()
		if wait > 0 {
			// need wait
			*reply = Resp{Code: 1, IP: ip, Phone: data.(PhoneData).Phone, Data: fmt.Sprintf("%d", wait)}
			srv.Log.Printf("info: There is active code. Expire in %d sec (%+v)", wait, reply)
			return nil
		}
		srv.Store.Del(ip)
		reply.Phone = data.(PhoneData).Phone
	}
	return nil
}

// -----------------------------------------------------------------------------

func (srv *Service) Phone(r *http.Request, args *ArgsKey, reply *Resp) error {

	ip := utils.GetIP(r, srv.IPField)

	//  1. Проверить корректность phone (32010)
	safe := phoneFilter.ReplaceAllLiteralString(args.Key, "")
	srv.Log.Printf("debug: Phone: %s", safe)
	if len(safe) != 10 {
		return &rpc.Error{Code: -32010, Message: "Incorrect phone number: " + safe}
	}

	//  2. По ip проверить отправку СМС за последние N сек
	data, ok := srv.Store.Get(ip)
	if ok {
		wait := data.(PhoneData).Stamp.Unix() + int64(srv.Config.SmsRetry) - time.Now().Unix()
		if wait > 0 {
			// need wait
			*reply = Resp{Code: 1, IP: ip, Phone: data.(PhoneData).Phone, Data: fmt.Sprintf("%d", wait)}
			srv.Log.Printf("info: There is active code. Expire in %d sec (%+v)", wait, reply)
			return nil
		}
		// expire(d)
		srv.Store.Del(ip)
	}

	//  3. Сгенерить случайный код
	//code, err := gostrgen.RandGen(5, gostrgen.Digit, "", "")
	//	var Reader io.Reader
	max := *big.NewInt(8999)
	codeB, err := rand.Int(rand.Reader, &max)
	if err != nil {
		srv.Log.Printf("error: Code generation error: ", err)
	}
	codeC := codeB.Int64() + 1000
	code := fmt.Sprintf("%d", codeC) // 4 digit

	//  4. сохранить [ip]{phone,code,stamp}
	srv.Store.Set(ip, PhoneData{Phone: safe, Code: code})

	//  5. || отправить смс, записать в логи ответ SMSC
	go smpp.Send(&srv.Config.Flags, srv.Log, safe, code)

	//  6. вернуть - сколько секунд до повтора *cfgSmsRetry*
	*reply = Resp{Code: 1, IP: ip, Phone: safe, Data: fmt.Sprintf("%d", srv.Config.SmsRetry)}
	return nil

}

// -----------------------------------------------------------------------------

func (srv *Service) Code(r *http.Request, args *ArgsKey, reply *Resp) error {

	ip := utils.GetIP(r, srv.IPField)

	//  1. Найти пару [Ip,code] и проверить наличие/совпадение code (32020) и просрочку по времени (32021)
	data, ok := srv.Store.Get(ip)
	if !ok || data.(PhoneData).Code != args.Key {
		// ToDo: во время этой задержки не принимать других запросов с этого ip
		srv.Log.Printf("warn: Incorrect code from ip %s (%s)", ip, args.Key)

		time.Sleep(time.Second * time.Duration(srv.Config.FailDelay)) // задержка от подбора
		return &rpc.Error{Code: -32020, Message: "Incorrect or unknown code"}
	}
	time.Sleep(time.Second) // минимум секунду ждем всегда
	wait := data.(PhoneData).Stamp.Unix() + int64(srv.Config.SmsRetry) - time.Now().Unix()
	srv.Store.Del(ip)
	if wait < 0 {
		return &rpc.Error{Code: -32021, Message: "Code is expired"}
	}

	//  2. Активация
	*reply, _ = srv.activate(ip, data.(PhoneData).Phone, false)
	return nil
}

// -----------------------------------------------------------------------------
// Расшифровать ключ, проверить его валидность (TODO)
func (srv *Service) parseKey(key string) (ret PhoneData, err error) {

	//	var value Cookie
	value := new(token.Attr)
	if err := srv.Token.Cryptor.Decode("satKey", key, value); err != nil {
		//	if err = a.Cryptor.Decode("satKey", key, &value); err == nil {
		srv.Log.Printf("debug: Got satKey %s (%+v)", key, value)
		ret = PhoneData{Phone: value.Record.Name, Stamp: value.Stamp}
	}
	//	panic(err)
	//	err = errors.New("TODO")
	return
}

// -----------------------------------------------------------------------------
// активация доступа телефону
func (srv *Service) activate(ip, phone string, isRepeat bool) (resp Resp, err error) {
	//  1. Запустить скрипт
	var rep int
	if isRepeat {
		rep = 1
	} else {
		rep = 0
	}
	status := "NONE"
	if srv.Hook != nil {
		status = (*srv.Hook)(ip, phone, fmt.Sprintf("%0d", rep))
	}

	//  3. Зашифровать и вернуть key *cfgAppKeyPass*
	var key string
	if !isRepeat {
		value := token.Attr{Record: token.Record{Name: phone}, Stamp: time.Now()}
		if encoded, err := srv.Token.Cryptor.Encode("satKey", value); err == nil {
			key = encoded
			srv.Log.Printf("debug: Set satKey %s (%+v)", key, value)
		}
	}
	resp = Resp{Code: 2 + rep, IP: ip, Phone: phone, Data: key, Status: status}

	return
}
