package services

import (
	"github.com/VidroX/cutcutfilm/services/identity/core/repositories"
	"github.com/VidroX/cutcutfilm/services/identity/core/services/permissions"
	"github.com/VidroX/cutcutfilm/services/identity/core/services/tokens"
)

const ServicesKey = "Services"

type Services struct {
	PermissionsService permissions.PermissionsService
	TokensService      tokens.TokensService
}

type ServiceDependencies struct {
	Repositories *repositories.Repositories
}

func Init(dependencies *ServiceDependencies) *Services {
	return &Services{
		PermissionsService: permissions.RegisterPermissionsService(dependencies.Repositories.PermissionsRepository),
		TokensService:      tokens.RegisterTokensService(dependencies.Repositories.TokensRepository),
	}
}
