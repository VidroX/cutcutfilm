package validation

import (
	"errors"
	"strings"

	nebulaErrors "github.com/VidroX/cutcutfilm-shared/errors"
	"github.com/VidroX/cutcutfilm/services/user/resources"
	"github.com/go-playground/validator/v10"
)

var (
	mainErrorCode         = "errors.user.validation."
	ErrValidationUnknown  = nebulaErrors.APIError{Code: mainErrorCode + "0", Error: errors.New(resources.KeysValidationUnknownError)}
	ErrValidationRequired = nebulaErrors.APIError{Code: mainErrorCode + "1", Error: errors.New(resources.KeysValidationRequiredError)}
	ErrIncorrectEmail     = nebulaErrors.APIError{Code: mainErrorCode + "2", Error: errors.New(resources.KeysValidationIncorrectEmailError)}
)

func ConstructValidationError(err nebulaErrors.APIError, field string) *nebulaErrors.APIError {
	if err.CustomInfo == nil {
		err.CustomInfo = make(map[string]interface{})
	}

	err.CustomInfo["field"] = strings.ToLower(field)

	return &err
}

func ProcessValidatorErrors(validatorError error) []*nebulaErrors.APIError {
	var apiErrors []*nebulaErrors.APIError

	if validatorError == nil {
		return apiErrors
	}

	for _, err := range validatorError.(validator.ValidationErrors) {
		switch err.ActualTag() {
		case "email":
			apiErrors = append(apiErrors, ConstructValidationError(ErrIncorrectEmail, err.Field()))
		case "required":
			apiErrors = append(apiErrors, ConstructValidationError(ErrValidationRequired, err.Field()))
		default:
			apiErrors = append(apiErrors, ConstructValidationError(ErrValidationUnknown, err.Field()))
		}
	}

	return apiErrors
}
