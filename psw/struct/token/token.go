package token

import (
	"time"
)

// Record holds profile data
type Record struct {
	ID    int64    // User ID
	Name  string   // User Name
	Roles []string // User Roles
}

// Attr holds Attr data
type Attr struct {
	Record
	Stamp time.Time
}
