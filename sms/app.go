// Package sms is an API service for authentication via SMS
package sms

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	rpc "github.com/gorilla/rpc/v2/json2"
	"gopkg.in/gorilla/securecookie.v1"
	"math/big"
	"net/http"
	"regexp"
	"time"

	"github.com/LeKovr/go-base/logger"
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

// App - Класс сервера API
type App struct {
	Store   *kvstore.Store
	Hook    *HookFunc
	Cryptor *securecookie.SecureCookie
	Log     *logger.Log
	Config  *Flags
}

// -----------------------------------------------------------------------------
// Functional options

// Config sets config struct
func Config(c *Flags) func(a *App) error {
	return func(a *App) error {
		return a.setConfig(c)
	}
}

// Hook sets onSuccess hook func
func Hook(f HookFunc) func(a *App) error {
	return func(a *App) error {
		return a.setHook(&f)
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

func (a *App) setHook(f *HookFunc) error {
	a.Hook = f
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

// New - Class constructor
func New(log *logger.Log, options ...func(a *App) error) (*App, error) {

	a := App{
		Log: log.WithField("in", "auth-sms"),
	}

	for _, option := range options {
		err := option(&a)
		if err != nil {
			return nil, err
		}
	}
	if a.Cryptor == nil {
		a.setCryptor()
	}
	a.Store, _ = kvstore.New(new(PhoneData), log, kvstore.Config(&kvstore.Flags{StoreName: a.Config.StoreName}))
	return &a, nil

}

// -----------------------------------------------------------------------------

// Init - если клиент уже авторизован вернуть Code=4, иначе - проверить остальные варианты
func (a *App) Init(r *http.Request, args *ArgsKey, reply *Resp) error {

	ip := r.Header.Get("Client-Ip")
	a.Log.Debugf("*** Init: %+v (%s)", args, ip)

	//		log.Printf("There is active code. Expire in %d sec (%+v)", wait, reply)

	//  1. Если key передан, корректен и не просрочен => Активация + факт реюза пишем в логи
	if args.Key != "" {
		keyData, err := a.parseKey(args.Key)
		if err == nil {
			*reply = Resp{Code: 4, Phone: keyData.Phone}
			a.Log.Debugf("*** Init: resp code: 4, phone: %s", keyData.Phone)
			return nil
		}
	}
	return a.initCheck(ip, reply)
}

// -----------------------------------------------------------------------------

// InitForced - если клиент уже авторизован, выполнить активацию, иначе - проверить остальные варианты
func (a *App) InitForced(r *http.Request, args *ArgsKey, reply *Resp) error {

	ip := r.Header.Get("Client-Ip")
	a.Log.Debugf("*** InitForced: %+v (%s)", args, ip)

	//		log.Printf("There is active code. Expire in %d sec (%+v)", wait, reply)

	//  1. Если key передан, корректен и не просрочен => Активация + факт реюза пишем в логи
	if args.Key != "" {
		keyData, err := a.parseKey(args.Key)
		if err == nil {
			*reply, _ = a.activate(ip, keyData.Phone, true)
			a.Log.Debugf("*** InitForced: activate, phone: %s", keyData.Phone)
			return nil
		}
	}
	return a.initCheck(ip, reply)
}

// -----------------------------------------------------------------------------

// initCheck - выполнить начальные проверки
func (a *App) initCheck(ip string, reply *Resp) error {

	//  2. Проверить баланс (32001)  *cfgAppMinBalance*
	ok, err := smpp.IsBalanceOk(&a.Config.Flags, a.Log)
	if err != nil {
		a.Log.Debugf("*** InitCheck: -32001, balance error (%+v)", err.Error())
		return &rpc.Error{Code: -32001, Message: "Balance error: " + err.Error()}
	}
	if !ok {
		a.Log.Debug("*** InitCheck: -32002, balance exceeded")
		return &rpc.Error{Code: -32002, Message: "Balance exceeded"}
	}

	*reply = Resp{Code: 0, IP: ip}

	//  3. Проверить, не было ли за последние *cfgAppSmsRetrySec* отправки с этого ip и вернуть - сколько секунд до повтора
	data, ok := a.Store.Get(ip)
	if ok {
		wait := data.(PhoneData).Stamp.Unix() + int64(a.Config.SmsRetry) - time.Now().Unix()
		if wait > 0 {
			// need wait
			*reply = Resp{Code: 1, IP: ip, Phone: data.(PhoneData).Phone, Data: fmt.Sprintf("%d", wait)}
			a.Log.Infof("There is active code. Expire in %d sec (%+v)", wait, reply)
			return nil
		}
		a.Store.Del(ip)
		reply.Phone = data.(PhoneData).Phone
		a.Log.Debugf("*** InitCheck: resp code: 0, expire phone: %s", reply.Phone)
	} else {
		a.Log.Debug("*** InitCheck: resp code: 0, no phone")
	}
	return nil
}

// -----------------------------------------------------------------------------

func (a *App) Phone(r *http.Request, args *ArgsKey, reply *Resp) error {

	ip := r.Header.Get("Client-Ip")
	a.Log.Debugf("*** Phone: %+v (%s)", args, ip)

	//  1. Проверить корректность phone (32010)
	safe := phoneFilter.ReplaceAllLiteralString(args.Key, "")
	a.Log.Debugf("Phone: %s", safe)
	if len(safe) != 10 {
		a.Log.Infof("*** Phone: -32010, incorrect phone (%s)", safe)
		return &rpc.Error{Code: -32010, Message: "Incorrect phone number: " + safe}
	}

	//  2. По ip проверить отправку СМС за последние N сек
	data, ok := a.Store.Get(ip)
	if ok {
		wait := data.(PhoneData).Stamp.Unix() + int64(a.Config.SmsRetry) - time.Now().Unix()
		if wait > 0 {
			// need wait
			*reply = Resp{Code: 1, IP: ip, Phone: data.(PhoneData).Phone, Data: fmt.Sprintf("%d", wait)}
			a.Log.Infof("There is active code. Expire in %d sec (%+v)", wait, reply)
			return nil
		}
		// expire(d)
		a.Store.Del(ip)
	}

	//  3. Сгенерить случайный код
	//code, err := gostrgen.RandGen(5, gostrgen.Digit, "", "")
	//	var Reader io.Reader
	max := *big.NewInt(8999)
	codeB, err := rand.Int(rand.Reader, &max)
	if err != nil {
		a.Log.Error("Code generation error: ", err)
	}
	codeC := codeB.Int64() + 1000
	code := fmt.Sprintf("%d", codeC) // 4 digit

	//  4. сохранить [ip]{phone,code,stamp}
	a.Store.Set(ip, PhoneData{Phone: safe, Code: code})

	//  5. || отправить смс, записать в логи ответ SMSC
	go smpp.Send(&a.Config.Flags, a.Log, safe, code)

	//  6. вернуть - сколько секунд до повтора *cfgSmsRetry*
	*reply = Resp{Code: 1, IP: ip, Phone: safe, Data: fmt.Sprintf("%d", a.Config.SmsRetry)}
	a.Log.Debugf("Phone: code = 1, send SMS to %s", safe)
	return nil

}

// -----------------------------------------------------------------------------

func (a *App) Code(r *http.Request, args *ArgsKey, reply *Resp) error {
	ip := r.Header.Get("Client-Ip")
	a.Log.Debugf("*** Code: %+v (%s)", args, ip)

	//  1. Найти пару [Ip,code] и проверить наличие/совпадение code (32020) и просрочку по времени (32021)
	data, ok := a.Store.Get(ip)
	if !ok || data.(PhoneData).Code != args.Key {
		// ToDo: во время этой задержки не принимать других запросов с этого ip
		a.Log.Warningf("Incorrect code from ip %s (%s)", ip, args.Key)

		time.Sleep(time.Second * time.Duration(a.Config.FailDelay)) // задержка от подбора
		return &rpc.Error{Code: -32020, Message: "Incorrect or unknown code"}
	}
	time.Sleep(time.Second) // минимум секунду ждем всегда
	wait := data.(PhoneData).Stamp.Unix() + int64(a.Config.SmsRetry) - time.Now().Unix()
	a.Store.Del(ip)
	if wait < 0 {
		a.Log.Infof("*** Code: -32021, code expired, phone (%s)", data.(PhoneData).Phone)
		return &rpc.Error{Code: -32021, Message: "Code is expired"}
	}

	//  2. Активация
	*reply, _ = a.activate(ip, data.(PhoneData).Phone, false)
	a.Log.Debugf("*** Code: activate, phone: %s", data.(PhoneData).Phone)
	return nil
}

// -----------------------------------------------------------------------------
// Расшифровать ключ, проверить его валидность (TODO)
func (a *App) parseKey(key string) (ret PhoneData, err error) {

	var value Cookie
	if err = a.Cryptor.Decode("satKey", key, &value); err == nil {
		a.Log.Debugf("Got satKey %s (%+v)", key, value)
		ret = PhoneData{Phone: value.Phone, Stamp: value.Stamp}
	}
	//	panic(err)
	//	err = errors.New("TODO")
	return
}

// -----------------------------------------------------------------------------
// активация доступа телефону
func (a *App) activate(ip, phone string, isRepeat bool) (resp Resp, err error) {
	//  1. Запустить скрипт
	var rep int
	if isRepeat {
		rep = 1
	} else {
		rep = 0
	}
	status := "NONE"
	if a.Hook != nil {
		status = (*a.Hook)(ip, phone, fmt.Sprintf("%0d", rep))
	}

	//  3. Зашифровать и вернуть key *cfgAppKeyPass*
	var key string
	if !isRepeat {
		value := Cookie{Phone: phone, Stamp: time.Now()}
		if encoded, err := a.Cryptor.Encode("satKey", value); err == nil {
			key = encoded
			a.Log.Debugf("Set satKey %s (%+v)", key, value)
		}
	}
	resp = Resp{Code: 2 + rep, IP: ip, Phone: phone, Data: key, Status: status}

	return
}
