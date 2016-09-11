package utils

import (
	"golang.org/x/crypto/bcrypt"
	"math/rand"
	"net/http"
	"time"

	"github.com/LeKovr/elsa-auth/psw/struct/token"
)

// -----------------------------------------------------------------------------

// RandomString returns random string of strlen length with chars from [a-zA-Z0-9]
func RandomString(strlen int) string {

	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	rand.Seed(time.Now().UTC().UnixNano())

	b := make([]byte, strlen)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}

// -----------------------------------------------------------------------------

// HashedPassword - generate hash of given string
func HashedPassword(s string) (string, error) {
	password := []byte(s)

	// Hashing the password with the default cost of 10
	hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	return string(hashedPassword), err
}

// CheckPassword - Compare hash and password
func CheckPassword(hashed, pass string) error {
	hashedPassword := []byte(hashed)
	password := []byte(pass)
	return bcrypt.CompareHashAndPassword(hashedPassword, password)
}

// GetIP fetches user ip from context
func GetIP(r *http.Request, field string) string {
	ctx := r.Context()
	d := ctx.Value(field)
	ip := d.(*string)
	return *ip
}

// GetMe fetches user session from context
func GetMe(r *http.Request, field string) *token.Record {
	ctx := r.Context()
	d := ctx.Value(field)
	if d == nil || d.(*token.Record) == nil {
		return nil
	}
	result := d.(*token.Record)
	return result
}
