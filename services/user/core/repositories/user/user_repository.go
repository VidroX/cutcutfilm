package user

import (
	"github.com/VidroX/cutcutfilm/services/user/core/database"
	"github.com/VidroX/cutcutfilm/services/user/graph/model"
)

type UserRepository interface {
	GetUser(id string) (*model.User, error)
}

func Get(database *database.NebulaDb) UserRepository {
	return &UserRepositoryGorm{
		database,
	}
}
