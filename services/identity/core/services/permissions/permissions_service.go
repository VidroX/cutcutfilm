package permissions

import (
	"github.com/VidroX/cutcutfilm-shared/utils"
	"github.com/VidroX/cutcutfilm/services/identity/core"
	nebulaErrors "github.com/VidroX/cutcutfilm/services/identity/core/errors"
	generalErrors "github.com/VidroX/cutcutfilm/services/identity/core/errors/general"
	"github.com/VidroX/cutcutfilm/services/identity/core/repositories/permissions"
)

type PermissionsService interface {
	GetUserPermissions(userId string) ([]core.Permission, *nebulaErrors.APIError)
}

type permissionsService struct {
	permissionsRepository permissions.PermissionsRepository
}

func (service *permissionsService) GetUserPermissions(userId string) ([]core.Permission, *nebulaErrors.APIError) {
	if utils.UtilString(userId).IsEmpty() {
		return nil, &generalErrors.ErrInternal
	}

	permissionsList, err := service.permissionsRepository.GetUserPermissions(userId)

	if err != nil {
		return nil, &generalErrors.ErrInternal
	}

	return permissionsList, nil
}

func RegisterPermissionsService(
	permissionsRepo permissions.PermissionsRepository,
) PermissionsService {
	return &permissionsService{
		permissionsRepository: permissionsRepo,
	}
}
