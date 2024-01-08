package tokens

import (
	"github.com/VidroX/cutcutfilm/services/identity/core/database"
	"github.com/VidroX/cutcutfilm/services/identity/core/database/models"
)

type TokensRepository interface {
	AddRevokedToken(token string) error
	GetRevokedToken(token string) (*models.RevokedToken, error)
}

func Get(database *database.NebulaDb) TokensRepository {
	return &TokensRepositoryGorm{
		database,
	}
}
