package permissions

import (
	"github.com/VidroX/cutcutfilm/services/identity/core"
	"github.com/VidroX/cutcutfilm/services/identity/core/database"
	"github.com/VidroX/cutcutfilm/services/identity/core/database/models"
	"strings"
)

type PermissionsRepositoryGorm struct {
	database *database.NebulaDb
}

func (repo *PermissionsRepositoryGorm) GetUserPermissions(id string) ([]core.Permission, error) {
	var permissionsModelList []models.UserPermission
	err := repo.database.Preload("Permission").Find(&permissionsModelList, "user_id = ?", strings.TrimSpace(id)).Error

	if err != nil {
		return nil, err
	}

	var permissionsList []core.Permission
	for _, permissionModel := range permissionsModelList {
		permissionsList = append(permissionsList, core.Permission{
			Name:        permissionModel.Permission.Name,
			Description: permissionModel.Permission.Description,
		})
	}

	return permissionsList, nil
}
