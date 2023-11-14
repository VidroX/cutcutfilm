package models

import "gorm.io/gorm"

type UserPermission struct {
	gorm.Model
	UserID         string     `json:"userId" gorm:"type:uuid"`
	PermissionName string     `json:"-"`
	Permission     Permission `json:"permission" gorm:"primaryKey;foreignKey:PermissionName;references:Name;OnDelete:CASCADE"`
}
