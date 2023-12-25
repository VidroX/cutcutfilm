package tokens

import (
	"github.com/VidroX/cutcutfilm/services/identity/core/database"
	"github.com/VidroX/cutcutfilm/services/identity/core/database/models"
)

type TokensRepositoryGorm struct {
	database *database.NebulaDb
}

func (repo *TokensRepositoryGorm) AddRevokedToken(token string) error {
	return repo.database.Create(&models.RevokedToken{Token: token}).Error
}

func (repo *TokensRepositoryGorm) GetRevokedToken(token string) (*models.RevokedToken, error) {
	var revokedToken models.RevokedToken
	err := repo.database.First(&revokedToken, "token = ?", token).Error

	if err != nil {
		return nil, err
	}

	return &revokedToken, nil
}
