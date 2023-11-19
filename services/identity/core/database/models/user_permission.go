package models

import "gorm.io/gorm"

type UserPermission struct {
	gorm.Model
	UserID           string     `json:"userId" gorm:"type:uuid"`
	PermissionAction string     `json:"-"`
	Permission       Permission `json:"permission" gorm:"primaryKey;foreignKey:PermissionAction;references:Action;OnDelete:CASCADE"`
}
