package tokens

import (
	nebulaErrors "github.com/VidroX/cutcutfilm-shared/errors"
	generalErrors "github.com/VidroX/cutcutfilm/services/identity/core/errors/general"
	"github.com/VidroX/cutcutfilm/services/identity/core/jwx"
	tokensRepo "github.com/VidroX/cutcutfilm/services/identity/core/repositories/tokens"
)

type TokensService interface {
	RevokeToken(token string) *nebulaErrors.APIError
	IsTokenRevoked(token string) bool
}

type tokensService struct {
	tokensRepository tokensRepo.TokensRepository
}

func (service *tokensService) RevokeToken(token string) *nebulaErrors.APIError {
	err := service.tokensRepository.AddRevokedToken(token)

	if err != nil {
		return &generalErrors.ErrInternal
	}

	return nil
}

func (service *tokensService) IsTokenRevoked(token string) bool {
	validatedToken, tokenType := jwx.ValidateToken(token)
	if validatedToken == nil || tokenType == nil {
		return true
	}

	revokedToken, _ := service.tokensRepository.GetRevokedToken(token)

	if revokedToken == nil {
		return false
	}

	return true
}

func RegisterTokensService(
	tokensRepo tokensRepo.TokensRepository,
) TokensService {
	return &tokensService{
		tokensRepository: tokensRepo,
	}
}
