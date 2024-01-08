package graph

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.40

import (
	"context"

	"github.com/VidroX/cutcutfilm-shared/contextuser"
	sharedErrors "github.com/VidroX/cutcutfilm-shared/errors"
	database "github.com/VidroX/cutcutfilm-shared/pagination"
	"github.com/VidroX/cutcutfilm-shared/permissions"
	"github.com/VidroX/cutcutfilm-shared/utils"
	"github.com/VidroX/cutcutfilm/services/user/core/errors/validation"
	"github.com/VidroX/cutcutfilm/services/user/graph"
	"github.com/VidroX/cutcutfilm/services/user/graph/model"
)

// Login is the resolver for the login field.
func (r *mutationResolver) Login(ctx context.Context, credential string, password string) (*model.UserWithToken, error) {
	user, err := r.Services.UserService.Login(ctx, credential, password)

	if err != nil && len(err) > 0 {
		sharedErrors.ProcessErrorsSlice(&ctx, graph.GetLocalizer(ctx), err)

		return nil, nil
	}

	return user, nil
}

// Register is the resolver for the register field.
func (r *mutationResolver) Register(ctx context.Context, userInfo model.UserRegistrationInput) (*model.UserWithToken, error) {
	user, err := r.Services.UserService.Register(ctx, userInfo)

	if err != nil && len(err) > 0 {
		sharedErrors.ProcessErrorsSlice(&ctx, graph.GetLocalizer(ctx), err)

		return nil, nil
	}

	return user, nil
}

// SetUserPermissions is the resolver for the setUserPermissions field.
func (r *mutationResolver) SetUserPermissions(ctx context.Context, userInfo model.SetUserPermissionsInput) (*model.User, error) {
	user, err := r.Services.UserService.SetUserPermissions(ctx, userInfo)

	if err != nil {
		return nil, sharedErrors.FormatError(graph.GetLocalizer(ctx), err)
	}

	return user, nil
}

// Logout is the resolver for the logout field.
func (r *mutationResolver) Logout(ctx context.Context) (bool, error) {
	isLoggedOut, err := r.Services.UserService.Logout(ctx)

	if err != nil {
		return isLoggedOut, sharedErrors.FormatError(graph.GetLocalizer(ctx), err)
	}

	return isLoggedOut, nil
}

// RefreshAccessToken is the resolver for the refreshAccessToken field.
func (r *queryResolver) RefreshAccessToken(ctx context.Context) (*model.Token, error) {
	token, err := r.Services.UserService.RefreshAccessToken(ctx)

	if err != nil {
		return nil, sharedErrors.FormatError(graph.GetLocalizer(ctx), err)
	}

	return token, nil
}

// User is the resolver for the user field.
func (r *queryResolver) User(ctx context.Context, userID *string) (*model.User, error) {
	currentUser := contextuser.GetCurrentUserFromContext(ctx)
	if currentUser != nil && userID == nil {
		userID = &currentUser.UserID
	}

	if userID == nil {
		return nil, sharedErrors.FormatError(
			graph.GetLocalizer(ctx),
			validation.ConstructValidationError(validation.ErrValidationRequired, "userId"),
		)
	}

	user, err := r.Entity().FindUserByID(ctx, *userID)

	if err != nil {
		return nil, err
	}

	return user, nil
}

// Users is the resolver for the users field.
func (r *queryResolver) Users(ctx context.Context, pagination *database.Pagination) (*model.UsersConnection, error) {
	usersConnection, err := r.Services.UserService.GetUsers(pagination)

	if err != nil {
		return nil, sharedErrors.FormatError(graph.GetLocalizer(ctx), err)
	}

	return usersConnection, nil
}

// Permissions is the resolver for the permissions field.
func (r *userResolver) Permissions(ctx context.Context, obj *model.User) ([]*permissions.Permission, error) {
	if obj == nil || utils.UtilString(obj.ID).IsEmpty() {
		return nil, sharedErrors.FormatError(
			graph.GetLocalizer(ctx),
			validation.ConstructValidationError(validation.ErrValidationUserNotFound, "user"),
		)
	}

	if obj.Permissions != nil {
		return obj.Permissions, nil
	}

	userPermissions, err := r.Services.UserService.GetUserPermissions(ctx, obj.ID)

	if err != nil {
		return nil, sharedErrors.FormatError(graph.GetLocalizer(ctx), err)
	}

	return userPermissions, nil
}

// Mutation returns graph.MutationResolver implementation.
func (r *Resolver) Mutation() graph.MutationResolver { return &mutationResolver{r} }

// Query returns graph.QueryResolver implementation.
func (r *Resolver) Query() graph.QueryResolver { return &queryResolver{r} }

// User returns graph.UserResolver implementation.
func (r *Resolver) User() graph.UserResolver { return &userResolver{r} }

type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
type userResolver struct{ *Resolver }
