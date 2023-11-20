package repositories

import (
	"github.com/VidroX/cutcutfilm/services/identity/core/database"
	"github.com/VidroX/cutcutfilm/services/identity/core/repositories/permissions"
)

const RepositoriesKey = "Repositories"

type Repositories struct {
	PermissionsRepository permissions.PermissionsRepository
}

type RepositoryDependencies struct {
	Database *database.NebulaDb
}

func Init(dependencies *RepositoryDependencies) *Repositories {
	return &Repositories{
		PermissionsRepository: permissions.Get(dependencies.Database),
	}
}
