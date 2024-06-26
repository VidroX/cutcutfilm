package model

import (
	"time"

	"github.com/VidroX/cutcutfilm-shared/permissions"
)

type User struct {
	ID               string                    `json:"id" gorm:"type:uuid;primarykey;default:gen_random_uuid()"`
	EMail            string                    `json:"email" validate:"required,gt=0,email" gorm:"column:email;uniqueIndex"`
	Username         string                    `json:"userName" validate:"required,gt=0" gorm:"uniqueIndex"`
	Password         string                    `json:"-" validate:"required,gte=6"`
	RegistrationDate time.Time                 `json:"registrationDate" gorm:"not null;default:current_timestamp"`
	Permissions      []*permissions.Permission `json:"permissions" gorm:"-"`
}

func (User) IsEntity() {}
