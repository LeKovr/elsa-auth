package account

// -----------------------------------------------------------------------------

// Record is a user account table record
type Record struct {
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

func (r Record) TableName() string {
	return "account"
}

// Records is an Account item slice
type Records []Record
