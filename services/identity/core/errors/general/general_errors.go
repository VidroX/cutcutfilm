package general

import (
	"errors"
	"github.com/VidroX/cutcutfilm/services/identity/resources"

	nebulaErrors "github.com/VidroX/cutcutfilm/services/identity/core/errors"
)

var (
	mainErrorCode            = "errors.identity.1."
	ErrInternal              = nebulaErrors.APIError{Code: mainErrorCode + "1", Error: errors.New(resources.KeysInternalError)}
	ErrNotEnoughPermissions  = nebulaErrors.APIError{Code: mainErrorCode + "2", Error: errors.New(resources.KeysNotEnoughPermissions)}
	ErrInvalidOrExpiredToken = nebulaErrors.APIError{Code: mainErrorCode + "3", Error: errors.New(resources.KeysInvalidOrExpiredTokenError)}
)
