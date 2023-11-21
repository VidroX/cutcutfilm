package user

import (
	"github.com/VidroX/cutcutfilm/services/user/core/database"
	"github.com/VidroX/cutcutfilm/services/user/graph/model"
)

type UserRepositoryGorm struct {
	database *database.NebulaDb
}

func (repo *UserRepositoryGorm) GetUser(id string) (*model.User, error) {
	return nil, nil
}
