package general

import (
	"errors"

	"github.com/VidroX/cutcutfilm/services/identity/resources"

	nebulaErrors "github.com/VidroX/cutcutfilm-shared/errors"
)

var (
	mainErrorCode            = "errors.identity.1."
	ErrInternal              = nebulaErrors.APIError{Code: mainErrorCode + "1", Error: errors.New(resources.KeysInternalError)}
	ErrNotEnoughPermissions  = nebulaErrors.APIError{Code: mainErrorCode + "2", Error: errors.New(resources.KeysNotEnoughPermissions)}
	ErrInvalidOrExpiredToken = nebulaErrors.APIError{Code: mainErrorCode + "3", Error: errors.New(resources.KeysInvalidOrExpiredTokenError)}
	ErrUserRequired          = nebulaErrors.APIError{Code: mainErrorCode + "4", Error: errors.New(resources.KeysUserRequiredError)}
	ErrNotFound              = nebulaErrors.APIError{Code: mainErrorCode + "5", Error: errors.New(resources.KeysNotFoundError)}
)
