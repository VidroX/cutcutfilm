package models

import "github.com/VidroX/cutcutfilm-shared/permissions"

type Permission struct {
	Action      string `json:"action" gorm:"primaryKey;type:varchar(255)"`
	Description string `json:"description" gorm:"type:text"`
}

func GetAllDatabasePermissionModels() []*Permission {
	var permissionModels []*Permission
	for _, permission := range permissions.AllPermissions {
		permissionModels = append(permissionModels, &Permission{
			Action:      permission.Action,
			Description: permission.Description,
		})
	}

	return permissionModels
}
