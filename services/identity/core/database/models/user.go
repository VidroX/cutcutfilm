package models

import (
	"github.com/VidroX/cutcutfilm-shared/contextuser"
)

type User struct {
	contextuser.ContextUser
	TokenIssuer string
}
