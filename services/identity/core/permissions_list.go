package core

import "github.com/VidroX/cutcutfilm/services/identity/core/database/models"

type Permission struct {
	Name        string
	Description string
}

var DefaultPermissions = []Permission{
	{Name: "read:self", Description: "Read data about yourself"},
	{Name: "write:self", Description: "Write data about yourself"},
}

var AllPermissions = []Permission{
	{Name: "read:admin", Description: "Admin read access"},
	{Name: "write:admin", Description: "Admin write access"},
	{Name: "read:self", Description: "Read data about yourself"},
	{Name: "write:self", Description: "Write data about yourself"},
}

func GetAllDatabasePermissionModels() []*models.Permission {
	var permissionModels []*models.Permission
	for _, permission := range AllPermissions {
		permissionModels = append(permissionModels, &models.Permission{
			Name:        permission.Name,
			Description: permission.Description,
		})
	}

	return permissionModels
}
