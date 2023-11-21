package services

import (
	"github.com/VidroX/cutcutfilm/services/user/core/repositories"
	"github.com/VidroX/cutcutfilm/services/user/core/services/user"
)

const ServicesKey = "Services"

type Services struct {
	UserService user.UserService
}

type ServiceDependencies struct {
	Repositories *repositories.Repositories
}

func Init(dependencies *ServiceDependencies) *Services {
	return &Services{
		UserService: user.RegisterUserService(dependencies.Repositories.UserRepository),
	}
}
