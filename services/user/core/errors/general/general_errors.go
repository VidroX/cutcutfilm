package general

import (
	"errors"

	"github.com/VidroX/cutcutfilm/services/user/resources"

	nebulaErrors "github.com/VidroX/cutcutfilm-shared/errors"
)

var (
	mainErrorCode           = "errors.user.1."
	ErrInternal             = nebulaErrors.APIError{Code: mainErrorCode + "1", Error: errors.New(resources.KeysInternalError)}
	ErrNotEnoughPermissions = nebulaErrors.APIError{Code: mainErrorCode + "2", Error: errors.New(resources.KeysNotEnoughPermissions)}
)
