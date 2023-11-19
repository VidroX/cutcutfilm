package permissions

import (
	"slices"
	"strings"

	"github.com/emirpasic/gods/sets/hashset"

	"github.com/VidroX/cutcutfilm-shared/permissions"
	"github.com/VidroX/cutcutfilm/services/identity/core/database"
	"github.com/VidroX/cutcutfilm/services/identity/core/database/models"
	"gorm.io/gorm"
)

type PermissionsRepositoryGorm struct {
	database *database.NebulaDb
}

func (repo *PermissionsRepositoryGorm) GetUserPermissions(id string) ([]permissions.Permission, error) {
	var permissionsModelList []models.UserPermission
	err := repo.database.Preload("Permission").Find(&permissionsModelList, "user_id = ?", strings.TrimSpace(id)).Error

	if err != nil {
		return nil, err
	}

	var permissionsList []permissions.Permission
	for _, permissionModel := range permissionsModelList {
		permissionsList = append(permissionsList, permissions.Permission{
			Action:      permissionModel.Permission.Action,
			Description: permissionModel.Permission.Description,
		})
	}

	return permissionsList, nil
}

func (repo *PermissionsRepositoryGorm) SetUserPermissions(id string, permissionSlice []permissions.Permission) error {
	userPermissions, err := repo.GetUserPermissions(id)

	if err != nil {
		return err
	}

	permissionsToDelete := getPermissionActionsToDelete(userPermissions, permissionSlice)
	permissionsToAdd := getDatabasePermissionDifference(id, permissionSlice, userPermissions)

	if len(permissionsToDelete) < 1 && len(permissionsToAdd) < 1 {
		return nil
	}

	err = repo.database.Transaction(func(tx *gorm.DB) error {
		err := tx.
			Delete(&models.UserPermission{}, map[string]interface{}{
				"user_id":           strings.TrimSpace(id),
				"permission_action": permissionsToDelete,
			}).
			Error

		if err != nil || len(permissionsToAdd) < 1 {
			return err
		}

		if err := tx.Create(permissionsToAdd).Error; err != nil {
			return err
		}

		return nil
	})

	return err
}

func getPermissionActionsToDelete(allPermissions []permissions.Permission, newPermissions []permissions.Permission) []string {
	newPermissionsSet := hashset.New()
	allPermissionsSet := hashset.New()

	for _, permission := range allPermissions {
		newPermissionsSet.Add(permission.Action)
	}

	for _, permission := range newPermissions {
		allPermissionsSet.Add(permission.Action)
	}

	permissionsDifference := newPermissionsSet.Difference(allPermissionsSet).Values()

	var deletePermissionActions []string
	for _, permission := range permissionsDifference {
		convertedPermission, ok := permission.(string)
		if !ok {
			continue
		}
		deletePermissionActions = append(deletePermissionActions, convertedPermission)
	}

	return deletePermissionActions
}

func getDatabasePermissionDifference(id string, allPermissions []permissions.Permission, newPermissions []permissions.Permission) []*models.UserPermission {
	newPermissionsSet := hashset.New()
	allPermissionsSet := hashset.New()

	for _, permission := range newPermissions {
		newPermissionsSet.Add(permission.Action)
	}

	for _, permission := range allPermissions {
		allPermissionsSet.Add(permission.Action)
	}

	permissionsDifference := allPermissionsSet.Difference(newPermissionsSet).Values()

	var difference []*models.UserPermission
	for _, permission := range permissionsDifference {
		convertedPermission, ok := permission.(string)
		permissionIndex := slices.IndexFunc(
			permissions.AllPermissions,
			func(p permissions.Permission) bool { return p.Action == convertedPermission },
		)

		if !ok || permissionIndex < 0 {
			continue
		}
		difference = append(difference, &models.UserPermission{
			UserID: id,
			Permission: models.Permission{
				Action:      permissions.AllPermissions[permissionIndex].Action,
				Description: permissions.AllPermissions[permissionIndex].Description,
			},
		})
	}

	return difference
}
