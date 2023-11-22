package user

import (
	"strings"

	"github.com/VidroX/cutcutfilm-shared/pagination"
	"github.com/VidroX/cutcutfilm/services/user/core/database"
	"github.com/VidroX/cutcutfilm/services/user/graph/model"
)

type UserRepositoryGorm struct {
	database *database.NebulaDb
}

func (repo *UserRepositoryGorm) GetUserById(id string) (*model.User, error) {
	var user model.User
	err := repo.database.First(&user, "id = ?", strings.TrimSpace(id)).Error

	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (repo *UserRepositoryGorm) GetUsers(paginationInfo *pagination.Pagination) ([]*model.User, int64, error) {
	var users []*model.User
	err := repo.database.
		Model(&model.User{}).
		Order("registration_date desc").
		Scopes(pagination.PaginationScope(paginationInfo)).
		Find(&users).
		Error

	if err != nil {
		return nil, 0, err
	}

	var total int64 = 0
	repo.database.Model(&model.User{}).Order("registration_date desc").Count(&total)

	return users, total, nil
}

func (repo *UserRepositoryGorm) GetUserByCredential(credential string) (*model.User, error) {
	var user model.User
	err := repo.database.First(&user, "email = ? or username = ?", credential, credential).Error

	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (repo *UserRepositoryGorm) CreateUser(user *model.User) error {
	return repo.database.Create(user).Error
}
