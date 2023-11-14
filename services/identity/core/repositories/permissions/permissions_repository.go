package permissions

import (
	"github.com/VidroX/cutcutfilm/services/identity/core"
	"github.com/VidroX/cutcutfilm/services/identity/core/database"
)

type PermissionsRepository interface {
	GetUserPermissions(id string) ([]core.Permission, error)
}

func Get(database *database.NebulaDb) PermissionsRepository {
	return &PermissionsRepositoryGorm{
		database,
	}
}
