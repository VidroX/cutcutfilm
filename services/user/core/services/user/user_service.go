package user

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"

	"connectrpc.com/connect"
	"github.com/VidroX/cutcutfilm-shared/contextuser"
	nebulaErrors "github.com/VidroX/cutcutfilm-shared/errors"
	"github.com/VidroX/cutcutfilm-shared/jwx"
	"github.com/VidroX/cutcutfilm-shared/pagination"
	"github.com/VidroX/cutcutfilm-shared/permissions"
	"github.com/VidroX/cutcutfilm-shared/tokens"
	"github.com/VidroX/cutcutfilm-shared/utils"
	"github.com/VidroX/cutcutfilm/services/user/core/environment"
	"github.com/VidroX/cutcutfilm/services/user/core/errors/general"
	generalErrors "github.com/VidroX/cutcutfilm/services/user/core/errors/general"
	"github.com/VidroX/cutcutfilm/services/user/core/errors/validation"
	userRepo "github.com/VidroX/cutcutfilm/services/user/core/repositories/user"
	"github.com/VidroX/cutcutfilm/services/user/graph/model"
	identityv1 "github.com/VidroX/cutcutfilm/services/user/proto/identity/v1"
	"github.com/VidroX/cutcutfilm/services/user/proto/identity/v1/identityv1connect"
	"github.com/alexedwards/argon2id"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
)

type UserService interface {
	GetUser(userId string) (*model.User, *nebulaErrors.APIError)
	GetUsers(paginationInfo *pagination.Pagination) (*model.UsersConnection, *nebulaErrors.APIError)
	GetUserPermissions(ctx context.Context, userId string) ([]*permissions.Permission, *nebulaErrors.APIError)
	Login(ctx context.Context, credential string, password string) (*model.UserWithToken, []*nebulaErrors.APIError)
	Register(ctx context.Context, userInfo model.UserRegistrationInput) (*model.UserWithToken, []*nebulaErrors.APIError)
	RefreshAccessToken(ctx context.Context) (*model.Token, *nebulaErrors.APIError)
	SetUserPermissions(ctx context.Context, userInfo model.SetUserPermissionsInput) (*model.User, *nebulaErrors.APIError)
}

type userService struct {
	userRepository        userRepo.UserRepository
	identityServiceClient *identityv1connect.IdentityServiceClient
	validator             *validator.Validate
}

func (service *userService) GetUser(userId string) (*model.User, *nebulaErrors.APIError) {
	if utils.UtilString(userId).IsEmpty() {
		return nil, validation.ConstructValidationError(validation.ErrValidationRequired, "userId")
	}

	if _, err := uuid.Parse(userId); err != nil {
		return nil, validation.ConstructValidationError(validation.ErrValidationUserNotFound, "userId")
	}

	user, err := service.userRepository.GetUserById(userId)

	var pgErr *pgconn.PgError
	if err != nil && (errors.Is(err, gorm.ErrRecordNotFound) || (errors.As(err, &pgErr) && pgErr.Code == pgerrcode.NoDataFound)) {
		return nil, validation.ConstructValidationError(validation.ErrValidationUserNotFound, "userId")
	} else if err != nil {
		return nil, &generalErrors.ErrInternal
	}

	return user, nil
}

func (service *userService) GetUsers(paginationInfo *pagination.Pagination) (*model.UsersConnection, *nebulaErrors.APIError) {
	users, total, err := service.userRepository.GetUsers(paginationInfo)

	if err != nil {
		return nil, &generalErrors.ErrInternal
	}

	return &model.UsersConnection{
		Node:     users,
		PageInfo: pagination.GetPageInfo(total, paginationInfo),
	}, nil
}

func (service *userService) GetUserPermissions(ctx context.Context, userId string) ([]*permissions.Permission, *nebulaErrors.APIError) {
	if utils.UtilString(userId).IsEmpty() {
		return nil, validation.ConstructValidationError(validation.ErrValidationRequired, "userId")
	}

	if _, err := uuid.Parse(userId); err != nil {
		return nil, validation.ConstructValidationError(validation.ErrValidationUserNotFound, "userId")
	}

	currentUser := contextuser.GetCurrentUserFromContext(ctx)
	canReadRequestedUser := currentUser != nil && (currentUser.HasPermission(permissions.AdminReadPermissionAction) ||
		(currentUser.UserID == userId && currentUser.HasPermission(permissions.UserReadSelfPermissionAction)))

	if !canReadRequestedUser {
		return nil, &general.ErrNotEnoughPermissions
	}

	req := connect.NewRequest(&identityv1.GetUserPermissionsRequest{
		UserId: userId,
	})

	req.Header().Add("X-Api-Key", os.Getenv(environment.KeysIdentityServiceApiKey))
	req.Header().Add("Authorization", currentUser.SuppliedToken)

	if service.identityServiceClient == nil {
		return nil, &general.ErrInternal
	}

	resp, err := (*service.identityServiceClient).GetUserPermissions(ctx, req)

	if err != nil {
		return nil, &general.ErrInternal
	}

	var userPermissions []*permissions.Permission
	for _, userPermission := range resp.Msg.Permissions {
		if userPermission == nil {
			continue
		}

		userPermissions = append(userPermissions, &permissions.Permission{
			Action:      userPermission.GetAction(),
			Description: userPermission.GetDescription(),
		})
	}

	return userPermissions, nil
}

func (service *userService) Login(ctx context.Context, credential string, password string) (*model.UserWithToken, []*nebulaErrors.APIError) {
	if utils.UtilString(credential).IsEmpty() || utils.UtilString(password).IsEmpty() {
		return nil, []*nebulaErrors.APIError{
			validation.ConstructValidationError(validation.ErrValidationCredentialUserNotFound, "EMail"),
			validation.ConstructValidationError(validation.ErrValidationCredentialUserNotFound, "Password"),
		}
	}

	dbUser, err := service.userRepository.GetUserByCredential(credential)

	if err != nil || dbUser == nil {
		return nil, []*nebulaErrors.APIError{
			validation.ConstructValidationError(validation.ErrValidationCredentialUserNotFound, "EMail"),
			validation.ConstructValidationError(validation.ErrValidationCredentialUserNotFound, "Password"),
		}
	}

	match, err := argon2id.ComparePasswordAndHash(password, dbUser.Password)

	if err != nil || !match {
		return nil, []*nebulaErrors.APIError{
			validation.ConstructValidationError(validation.ErrValidationCredentialUserNotFound, "EMail"),
			validation.ConstructValidationError(validation.ErrValidationCredentialUserNotFound, "Password"),
		}
	}

	userTokens, err2 := getUserTokens(service.identityServiceClient, ctx, dbUser.ID)

	if err != nil {
		return nil, []*nebulaErrors.APIError{err2}
	}

	return &model.UserWithToken{
		User: dbUser,
		AccessToken: &model.Token{
			Type:  tokens.TokenTypeAccess,
			Token: userTokens.Access,
		},
		RefreshToken: &model.Token{
			Type:  tokens.TokenTypeRefresh,
			Token: userTokens.Refresh,
		},
	}, nil
}

func (service *userService) Register(ctx context.Context, userInfo model.UserRegistrationInput) (*model.UserWithToken, []*nebulaErrors.APIError) {
	dbUser := model.User{
		EMail:    userInfo.Email,
		Username: userInfo.UserName,
		Password: userInfo.Password,
	}

	err := service.validator.Struct(&dbUser)

	if apiErrors := validation.ProcessValidatorErrors(err); apiErrors != nil && len(apiErrors) > 0 {
		return nil, apiErrors
	}

	hashedPassword, err := argon2id.CreateHash(dbUser.Password, argon2id.DefaultParams)

	if err != nil {
		return nil, []*nebulaErrors.APIError{&generalErrors.ErrInternal}
	}

	dbUser.Password = hashedPassword

	err = service.userRepository.CreateUser(&dbUser)

	var pgErr *pgconn.PgError
	if err != nil && (errors.Is(err, gorm.ErrDuplicatedKey) || (errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation)) {
		if errors.As(err, &pgErr) && strings.Contains(pgErr.Detail, "(email)=") {
			return nil, []*nebulaErrors.APIError{validation.ConstructValidationError(validation.ErrUserEmailAlreadyRegistered, "EMail")}
		} else if errors.As(err, &pgErr) && strings.Contains(pgErr.Detail, "(username)=") {
			return nil, []*nebulaErrors.APIError{validation.ConstructValidationError(validation.ErrUserNameAlreadyRegistered, "Username")}
		}
	} else if err != nil {
		return nil, []*nebulaErrors.APIError{&generalErrors.ErrInternal}
	}

	userTokens, err2 := getUserTokens(service.identityServiceClient, ctx, dbUser.ID)

	if err != nil {
		return nil, []*nebulaErrors.APIError{err2}
	}

	return &model.UserWithToken{
		User: &dbUser,
		AccessToken: &model.Token{
			Type:  tokens.TokenTypeAccess,
			Token: userTokens.Access,
		},
		RefreshToken: &model.Token{
			Type:  tokens.TokenTypeRefresh,
			Token: userTokens.Refresh,
		},
	}, nil
}

func (service *userService) RefreshAccessToken(ctx context.Context) (*model.Token, *nebulaErrors.APIError) {
	currentUser := contextuser.GetCurrentUserFromContext(ctx)

	if currentUser == nil {
		return nil, &general.ErrNotEnoughPermissions
	}

	req := connect.NewRequest(&identityv1.RefreshTokenRequest{})

	req.Header().Add("X-Api-Key", os.Getenv(environment.KeysIdentityServiceApiKey))
	req.Header().Add("Authorization", currentUser.SuppliedToken)

	if service.identityServiceClient == nil {
		return nil, &general.ErrInternal
	}

	resp, err := (*service.identityServiceClient).RefreshToken(ctx, req)

	if err != nil {
		return nil, &general.ErrInternal
	}

	return &model.Token{
		Type:  tokens.TokenTypeRefresh,
		Token: resp.Msg.GetToken(),
	}, nil
}

func (service *userService) SetUserPermissions(ctx context.Context, userInfo model.SetUserPermissionsInput) (*model.User, *nebulaErrors.APIError) {
	currentUser := contextuser.GetCurrentUserFromContext(ctx)

	if currentUser == nil || !currentUser.HasPermission(permissions.AdminWritePermissionAction) {
		return nil, &general.ErrNotEnoughPermissions
	}

	var normalizedPermissions []string

	for _, permissionString := range userInfo.Permissions {
		if permissionString == nil {
			continue
		}

		normalizedPermissions = append(normalizedPermissions, *permissionString)
	}

	noAdminPermissions := userInfo.UserID == currentUser.UserID && (!slices.Contains(normalizedPermissions, permissions.AdminReadPermissionAction) ||
		!slices.Contains(normalizedPermissions, permissions.AdminWritePermissionAction))

	if noAdminPermissions {
		return nil, &general.ErrNotEnoughPermissions
	}

	req := connect.NewRequest(&identityv1.SetUserPermissionsRequest{
		UserId:      userInfo.UserID,
		Permissions: normalizedPermissions,
	})

	req.Header().Add("X-Api-Key", os.Getenv(environment.KeysIdentityServiceApiKey))
	req.Header().Add("Authorization", currentUser.SuppliedToken)

	if service.identityServiceClient == nil {
		return nil, &general.ErrInternal
	}

	_, err := (*service.identityServiceClient).SetUserPermissions(ctx, req)

	if err != nil {
		return nil, &general.ErrInternal
	}

	user, err2 := service.GetUser(userInfo.UserID)

	if err2 != nil {
		return nil, &general.ErrInternal
	}

	return user, nil
}

func getUserTokens(client *identityv1connect.IdentityServiceClient, ctx context.Context, userId string) (*model.TokenCollection, *nebulaErrors.APIError) {
	req := connect.NewRequest(&identityv1.IssueTokensRequest{
		UserId: userId,
	})

	req.Header().Add("X-Api-Key", os.Getenv(environment.KeysIdentityServiceApiKey))
	req.Header().Add("Authorization", jwx.CreateApplicationRequestToken())

	if client == nil {
		return nil, &general.ErrInternal
	}

	resp, err := (*client).IssueTokens(ctx, req)

	if err != nil {
		return nil, &general.ErrInternal
	}

	return &model.TokenCollection{
		Access:  resp.Msg.GetAccessToken(),
		Refresh: resp.Msg.GetRefreshToken(),
	}, nil
}

func RegisterUserService(
	userRepository userRepo.UserRepository,
	identityServiceClient *identityv1connect.IdentityServiceClient,
	validator *validator.Validate,
) *userService {
	return &userService{
		userRepository:        userRepository,
		identityServiceClient: identityServiceClient,
		validator:             validator,
	}
}
