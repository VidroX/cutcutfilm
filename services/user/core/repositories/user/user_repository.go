package user

import (
	"github.com/VidroX/cutcutfilm-shared/pagination"
	"github.com/VidroX/cutcutfilm/services/user/core/database"
	"github.com/VidroX/cutcutfilm/services/user/graph/model"
)

type UserRepository interface {
	GetUserById(id string) (*model.User, error)
	GetUsers(paginationInfo *pagination.Pagination) ([]*model.User, int64, error)
	GetUserByCredential(credential string) (*model.User, error)
	CreateUser(user *model.User) error
}

func Get(database *database.NebulaDb) UserRepository {
	return &UserRepositoryGorm{
		database,
	}
}
