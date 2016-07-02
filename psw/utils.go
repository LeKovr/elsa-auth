package psw

import (
	"golang.org/x/crypto/bcrypt"
	"math/rand"
	"time"
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

// hashedPassword - generate hash of given string
func hashedPassword(s string) (string, error) {
	password := []byte(s)

	// Hashing the password with the default cost of 10
	hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	return string(hashedPassword), err
}

// checkPassword - Compare hash and password
func checkPassword(hashed, pass string) error {
	hashedPassword := []byte(hashed)
	password := []byte(pass)
	return bcrypt.CompareHashAndPassword(hashedPassword, password)
}
