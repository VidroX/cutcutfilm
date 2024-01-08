package permissions

import (
	"github.com/VidroX/cutcutfilm-shared/permissions"
	"github.com/VidroX/cutcutfilm/services/identity/core/database"
)

type PermissionsRepository interface {
	GetUserPermissions(id string) ([]permissions.Permission, error)
	SetUserPermissions(id string, permissionSlice []permissions.Permission) error
}

func Get(database *database.NebulaDb) PermissionsRepository {
	return &PermissionsRepositoryGorm{
		database,
	}
}
