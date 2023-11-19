package permissions

import (
	"errors"

	nebulaErrors "github.com/VidroX/cutcutfilm-shared/errors"
	"github.com/VidroX/cutcutfilm-shared/permissions"
	"github.com/VidroX/cutcutfilm-shared/utils"
	generalErrors "github.com/VidroX/cutcutfilm/services/identity/core/errors/general"
	permissionsRepo "github.com/VidroX/cutcutfilm/services/identity/core/repositories/permissions"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
)

type PermissionsService interface {
	GetUserPermissions(userId string) ([]permissions.Permission, *nebulaErrors.APIError)
	GetOrSetDefaultUserPermissions(userId string) ([]permissions.Permission, *nebulaErrors.APIError)
	SetUserPermissions(userId string, permissionsSlice []permissions.Permission) *nebulaErrors.APIError
}

type permissionsService struct {
	permissionsRepository permissionsRepo.PermissionsRepository
}

func (service *permissionsService) GetUserPermissions(userId string) ([]permissions.Permission, *nebulaErrors.APIError) {
	if utils.UtilString(userId).IsEmpty() {
		return nil, &generalErrors.ErrUserRequired
	}

	permissionsList, err := service.permissionsRepository.GetUserPermissions(userId)

	if err != nil {
		return nil, &generalErrors.ErrInternal
	}

	return permissionsList, nil
}

func (service *permissionsService) GetOrSetDefaultUserPermissions(userId string) ([]permissions.Permission, *nebulaErrors.APIError) {
	if utils.UtilString(userId).IsEmpty() {
		return nil, &generalErrors.ErrUserRequired
	}

	permissionsList, err := service.permissionsRepository.GetUserPermissions(userId)

	var pgErr *pgconn.PgError
	if err != nil && (errors.Is(err, gorm.ErrRecordNotFound) || (errors.As(err, &pgErr) && pgErr.Code == pgerrcode.NoDataFound)) {
		err2 := service.permissionsRepository.SetUserPermissions(userId, permissions.DefaultPermissions)

		if err2 != nil {
			return nil, &generalErrors.ErrInternal
		}

		permissionsList = permissions.DefaultPermissions
	} else if err != nil {
		return nil, &generalErrors.ErrInternal
	}

	return permissionsList, nil
}

func (service *permissionsService) SetUserPermissions(userId string, permissionsSlice []permissions.Permission) *nebulaErrors.APIError {
	if utils.UtilString(userId).IsEmpty() {
		return &generalErrors.ErrUserRequired
	}

	err := service.permissionsRepository.SetUserPermissions(userId, permissionsSlice)

	if err != nil {
		return &generalErrors.ErrInternal
	}

	return nil
}

func RegisterPermissionsService(
	permissionsRepo permissionsRepo.PermissionsRepository,
) PermissionsService {
	return &permissionsService{
		permissionsRepository: permissionsRepo,
	}
}
