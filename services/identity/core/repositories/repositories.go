package repositories

import (
	"github.com/VidroX/cutcutfilm/services/identity/core/database"
	"github.com/VidroX/cutcutfilm/services/identity/core/repositories/permissions"
	"github.com/VidroX/cutcutfilm/services/identity/core/repositories/tokens"
)

const RepositoriesKey = "Repositories"

type Repositories struct {
	PermissionsRepository permissions.PermissionsRepository
	TokensRepository      tokens.TokensRepository
}

type RepositoryDependencies struct {
	Database *database.NebulaDb
}

func Init(dependencies *RepositoryDependencies) *Repositories {
	return &Repositories{
		PermissionsRepository: permissions.Get(dependencies.Database),
		TokensRepository:      tokens.Get(dependencies.Database),
	}
}
