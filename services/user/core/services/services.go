package services

import (
	"github.com/VidroX/cutcutfilm/services/user/core/repositories"
	"github.com/VidroX/cutcutfilm/services/user/core/services/user"
	"github.com/VidroX/cutcutfilm/services/user/proto/identity/v1/identityv1connect"
	"github.com/go-playground/validator/v10"
)

const ServicesKey = "Services"

type Services struct {
	UserService user.UserService
}

type ServiceDependencies struct {
	Repositories          *repositories.Repositories
	IdentityServiceClient *identityv1connect.IdentityServiceClient
	Validator             *validator.Validate
}

func Init(dependencies *ServiceDependencies) *Services {
	return &Services{
		UserService: user.RegisterUserService(
			dependencies.Repositories.UserRepository,
			dependencies.IdentityServiceClient,
			dependencies.Validator,
		),
	}
}
