package repositories

import (
	"github.com/VidroX/cutcutfilm/services/user/core/database"
	"github.com/VidroX/cutcutfilm/services/user/core/repositories/user"
)

const RepositoriesKey = "Repositories"

type Repositories struct {
	UserRepository user.UserRepository
}

type RepositoryDependencies struct {
	Database *database.NebulaDb
}

func Init(dependencies *RepositoryDependencies) *Repositories {
	return &Repositories{
		UserRepository: user.Get(dependencies.Database),
	}
}
