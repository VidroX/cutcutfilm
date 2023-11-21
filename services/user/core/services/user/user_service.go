package user

import (
	nebulaErrors "github.com/VidroX/cutcutfilm-shared/errors"
	"github.com/VidroX/cutcutfilm-shared/utils"
	"github.com/VidroX/cutcutfilm/services/user/core/errors/validation"
	userRepo "github.com/VidroX/cutcutfilm/services/user/core/repositories/user"
	"github.com/VidroX/cutcutfilm/services/user/graph/model"
)

type UserService interface {
	GetUser(userId string) (*model.User, *nebulaErrors.APIError)
}

type userService struct {
	userRepository userRepo.UserRepository
}

func (service *userService) GetUser(userId string) (*model.User, *nebulaErrors.APIError) {
	if utils.UtilString(userId).IsEmpty() {
		return nil, validation.ConstructValidationError(validation.ErrValidationRequired, "userId")
	}

	return nil, nil
}

func RegisterUserService(
	userRepository userRepo.UserRepository,
) *userService {
	return &userService{
		userRepository: userRepository,
	}
}
