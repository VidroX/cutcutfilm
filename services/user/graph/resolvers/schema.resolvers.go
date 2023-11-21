package graph

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.40

import (
	"context"
	"fmt"

	database "github.com/VidroX/cutcutfilm-shared/pagination"
	"github.com/VidroX/cutcutfilm/services/user/graph"
	"github.com/VidroX/cutcutfilm/services/user/graph/model"
)

// Login is the resolver for the login field.
func (r *mutationResolver) Login(ctx context.Context, credential string, password string) (*model.UserWithToken, error) {
	panic(fmt.Errorf("not implemented: Login - login"))
}

// Register is the resolver for the register field.
func (r *mutationResolver) Register(ctx context.Context, userInfo model.UserRegistrationInput) (*model.UserWithToken, error) {
	panic(fmt.Errorf("not implemented: Register - register"))
}

// RefreshAccessToken is the resolver for the refreshAccessToken field.
func (r *queryResolver) RefreshAccessToken(ctx context.Context) (*model.Token, error) {
	panic(fmt.Errorf("not implemented: RefreshAccessToken - refreshAccessToken"))
}

// User is the resolver for the user field.
func (r *queryResolver) User(ctx context.Context, userID *string) (*model.User, error) {
	panic(fmt.Errorf("not implemented: User - user"))
}

// Users is the resolver for the users field.
func (r *queryResolver) Users(ctx context.Context, pagination *database.Pagination) (*model.UsersConnection, error) {
	panic(fmt.Errorf("not implemented: Users - users"))
}

// Mutation returns graph.MutationResolver implementation.
func (r *Resolver) Mutation() graph.MutationResolver { return &mutationResolver{r} }

// Query returns graph.QueryResolver implementation.
func (r *Resolver) Query() graph.QueryResolver { return &queryResolver{r} }

type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
