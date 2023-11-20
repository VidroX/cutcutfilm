package services

import (
	"github.com/VidroX/cutcutfilm/services/identity/core/repositories"
	"github.com/VidroX/cutcutfilm/services/identity/core/services/permissions"
)

const ServicesKey = "Services"

type Services struct {
	PermissionsService permissions.PermissionsService
}

type ServiceDependencies struct {
	Repositories *repositories.Repositories
}

func Init(dependencies *ServiceDependencies) *Services {
	return &Services{
		PermissionsService: permissions.RegisterPermissionsService(dependencies.Repositories.PermissionsRepository),
	}
}
