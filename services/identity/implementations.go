package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"slices"
	"strings"
	"time"

	b64 "encoding/base64"

	"connectrpc.com/connect"
	nebulaErrors "github.com/VidroX/cutcutfilm-shared/errors"
	"github.com/VidroX/cutcutfilm-shared/permissions"
	"github.com/VidroX/cutcutfilm-shared/tokens"
	"github.com/VidroX/cutcutfilm-shared/translator"
	"github.com/VidroX/cutcutfilm-shared/utils"
	"github.com/VidroX/cutcutfilm/services/identity/core/database/models"
	"github.com/VidroX/cutcutfilm/services/identity/core/environment"
	"github.com/VidroX/cutcutfilm/services/identity/core/jwx"
	pb "github.com/VidroX/cutcutfilm/services/identity/proto/identity/v1"
	"github.com/VidroX/cutcutfilm/services/identity/resources"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *server) IssueTokens(ctx context.Context, req *connect.Request[pb.IssueTokensRequest]) (*connect.Response[pb.IssueTokensResponse], error) {
	localizer, ok := ctx.Value(translator.Key).(*translator.NebulaLocalizer)
	if !ok || localizer == nil {
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	user, ok := ctx.Value("user").(models.User)

	if !ok || user.TokenType != tokens.TokenTypeApplicationRequest {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Println("Cannot issue tokens: user is not authorized or does not have a valid token type")
		}

		return nil, status.Errorf(
			codes.Unauthenticated,
			translator.WithKey(resources.KeysInvalidOrExpiredTokenError).Translate(localizer),
		)
	}

	userId := req.Msg.GetUserId()
	_, err := uuid.Parse(userId)

	if utils.UtilString(userId).IsEmpty() || err != nil {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Println("Cannot issue tokens: userId is empty")
		}

		return nil, status.Errorf(codes.Internal, translator.WithKey(resources.KeysUserRequiredError).Translate(localizer))
	}

	_, err2 := s.services.PermissionsService.GetOrSetDefaultUserPermissions(userId)

	if err2 != nil {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Println("Cannot issue tokens: permissions fetch failed")
		}

		return nil, status.Errorf(codes.Internal, translator.WithKey(resources.KeysInternalError).Translate(localizer))
	}

	return connect.NewResponse(&pb.IssueTokensResponse{
		AccessToken: jwx.CreateToken(&jwx.TokenParams{
			TokenType:   tokens.TokenTypeAccess,
			UserId:      &userId,
			AddAudience: true,
		}),
		RefreshToken: jwx.CreateToken(&jwx.TokenParams{
			TokenType:   tokens.TokenTypeRefresh,
			UserId:      &userId,
			AddAudience: true,
		}),
	}), nil
}

func (s *server) IssueServiceToken(ctx context.Context, req *connect.Request[pb.IssueServiceTokenRequest]) (*connect.Response[pb.IssueServiceTokenResponse], error) {
	localizer, ok := ctx.Value(translator.Key).(*translator.NebulaLocalizer)
	if !ok || localizer == nil {
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	user, ok := ctx.Value("user").(models.User)

	if !ok || user.TokenType == tokens.TokenTypeApplicationRequest {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Println("Cannot issue service token: user is not authorized or does not have a valid token type")
		}

		return nil, status.Errorf(
			codes.Unauthenticated,
			translator.WithKey(resources.KeysInvalidOrExpiredTokenError).Translate(localizer),
		)
	}

	_, err := uuid.Parse(user.UserID)

	if utils.UtilString(user.UserID).IsEmpty() || err != nil {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Println("Cannot issue service token: userId is empty")
		}

		return nil, status.Errorf(codes.Internal, translator.WithKey(resources.KeysUserRequiredError).Translate(localizer))
	}

	permissionsSlice, err2 := s.services.PermissionsService.GetOrSetDefaultUserPermissions(user.UserID)

	if err2 != nil {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Println("Cannot issue service token: permission fetch failed")
		}

		return nil, status.Errorf(codes.Internal, translator.WithKey(resources.KeysInternalError).Translate(localizer))
	}

	return connect.NewResponse(&pb.IssueServiceTokenResponse{
		Token: jwx.CreateToken(&jwx.TokenParams{
			TokenType:   user.TokenType,
			UserId:      &user.UserID,
			Permissions: permissionsSlice,
			ExpiryTime:  &jwx.DurationWrapper{Duration: time.Minute},
			AddAudience: false,
		}),
	}), nil
}

func (s *server) RefreshToken(ctx context.Context, req *connect.Request[pb.RefreshTokenRequest]) (*connect.Response[pb.RefreshTokenResponse], error) {
	localizer, ok := ctx.Value(translator.Key).(*translator.NebulaLocalizer)
	if !ok || localizer == nil {
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	user, ok := ctx.Value("user").(models.User)

	if !ok || user.TokenType != tokens.TokenTypeRefresh {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Printf("Cannot issue new access token: user is not authorized or does not have a valid token type (current token type: %s)\n", user.TokenType.String())
		}

		return nil, status.Errorf(
			codes.Unauthenticated,
			translator.WithKey(resources.KeysInvalidOrExpiredTokenError).Translate(localizer),
		)
	}

	permissionsSlice, err := s.services.PermissionsService.GetOrSetDefaultUserPermissions(user.UserID)

	if err != nil {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Println("Cannot issue service token: permissions fetch failed")
		}

		return nil, status.Errorf(codes.Internal, translator.WithKey(resources.KeysInternalError).Translate(localizer))
	}

	return connect.NewResponse(&pb.RefreshTokenResponse{
		Token: jwx.CreateToken(&jwx.TokenParams{
			TokenType:   tokens.TokenTypeAccess,
			UserId:      &user.UserID,
			Permissions: permissionsSlice,
			AddAudience: true,
		}),
	}), nil
}

func (s *server) SetUserPermissions(ctx context.Context, req *connect.Request[pb.SetUserPermissionsRequest]) (*connect.Response[pb.SetUserPermissionsResponse], error) {
	localizer, ok := ctx.Value(translator.Key).(*translator.NebulaLocalizer)
	if !ok || localizer == nil {
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	user, ok := ctx.Value("user").(models.User)

	if !ok || user.TokenType != tokens.TokenTypeAccess {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Println("Cannot set user permissions: user is not authorized or does not have a valid token type")
		}

		return nil, status.Errorf(
			codes.Unauthenticated,
			translator.WithKey(resources.KeysInvalidOrExpiredTokenError).Translate(localizer),
		)
	}

	permissionsSlice := mapStringPermissionsToPermissions(req.Msg.GetPermissions())

	requestedUserId := req.Msg.GetUserId()
	if utils.UtilString(requestedUserId).IsEmpty() {
		requestedUserId = user.UserID
	}

	isAdmin := user.HasPermission(permissions.AdminWritePermissionAction)

	if !isAdmin {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Printf("Cannot set user permissions: user %s is not admin\n", user.UserID)
		}

		return nil, status.Errorf(
			codes.Internal,
			translator.WithKey(resources.KeysNotEnoughPermissions).Translate(localizer),
		)
	}

	if requestedUserId == user.UserID {
		hasAdminWritePermission := slices.ContainsFunc(
			permissionsSlice,
			func(p permissions.Permission) bool { return p.Action == permissions.AdminWritePermissionAction },
		)
		hasAdminReadPermission := slices.ContainsFunc(
			permissionsSlice,
			func(p permissions.Permission) bool { return p.Action == permissions.AdminReadPermissionAction },
		)

		if !hasAdminReadPermission || !hasAdminWritePermission {
			if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
				log.Println("Cannot set user permissions: user cannot remove admin permissions from itself")
			}

			return nil, status.Errorf(
				codes.Internal,
				translator.WithKey(resources.KeysNotEnoughPermissions).Translate(localizer),
			)
		}
	}

	err := s.services.PermissionsService.SetUserPermissions(requestedUserId, permissionsSlice)

	if err != nil {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Println("Cannot set user permissions")
		}

		return nil, status.Errorf(codes.Internal, translator.WithKey(resources.KeysInternalError).Translate(localizer))
	}

	updatedUser := &pb.UserWithPermissions{
		UserId:      requestedUserId,
		Permissions: mapPermissionsToProtoPermissions(permissionsSlice),
	}

	return connect.NewResponse(&pb.SetUserPermissionsResponse{
		Token: jwx.CreateToken(&jwx.TokenParams{
			TokenType:   user.TokenType,
			UserId:      &requestedUserId,
			Permissions: permissionsSlice,
			AddAudience: true,
		}),
		User: updatedUser,
	}), nil
}

func (s *server) GetUserPermissions(ctx context.Context, req *connect.Request[pb.GetUserPermissionsRequest]) (*connect.Response[pb.GetUserPermissionsResponse], error) {
	localizer, ok := ctx.Value(translator.Key).(*translator.NebulaLocalizer)
	if !ok || localizer == nil {
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	user, ok := ctx.Value("user").(models.User)

	if !ok || user.TokenType != tokens.TokenTypeAccess {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Println("Cannot get user permissions: user is not authorized or does not have a valid token type")
		}

		return nil, status.Errorf(
			codes.Unauthenticated,
			translator.WithKey(resources.KeysInvalidOrExpiredTokenError).Translate(localizer),
		)
	}

	requestedUserId := req.Msg.GetUserId()
	if utils.UtilString(requestedUserId).IsEmpty() {
		requestedUserId = user.UserID
	}

	isAdmin := user.HasPermission(permissions.AdminReadPermissionAction)

	if !isAdmin && requestedUserId != user.UserID {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Printf("Cannot get user permissions: user %s does not have admin permissions\n", user.UserID)
		}

		return nil, status.Errorf(
			codes.Internal,
			translator.WithKey(resources.KeysNotEnoughPermissions).Translate(localizer),
		)
	}

	var permissionsSlice []permissions.Permission
	var err *nebulaErrors.APIError

	if requestedUserId == user.UserID {
		permissionsSlice, err = s.services.PermissionsService.GetOrSetDefaultUserPermissions(requestedUserId)
	} else {
		permissionsSlice, err = s.services.PermissionsService.GetUserPermissions(requestedUserId)
	}

	if err != nil {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Println("Cannot get user permissions")
		}

		return nil, status.Errorf(codes.Internal, translator.WithKey(resources.KeysInternalError).Translate(localizer))
	}

	return connect.NewResponse(&pb.GetUserPermissionsResponse{
		UserId:      requestedUserId,
		Permissions: mapPermissionsToProtoPermissions(permissionsSlice),
	}), nil
}

func (s *server) ValidateUser(ctx context.Context, req *connect.Request[pb.ValidateUserRequest]) (*connect.Response[pb.ValidateUserResponse], error) {
	localizer, ok := ctx.Value(translator.Key).(*translator.NebulaLocalizer)
	if !ok || localizer == nil {
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	user, ok := ctx.Value("user").(models.User)

	if !ok {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Println("Cannot validate user: user is not authorized or does not have a valid token type")
		}

		return nil, status.Errorf(
			codes.Unauthenticated,
			translator.WithKey(resources.KeysInvalidOrExpiredTokenError).Translate(localizer),
		)
	}

	var permissionsSlice []permissions.Permission
	var err *nebulaErrors.APIError

	permissionsSlice, err = s.services.PermissionsService.GetOrSetDefaultUserPermissions(user.UserID)

	if err != nil {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Println("Cannot validate user: cannot get or set user permissions")
		}

		return nil, status.Errorf(codes.Internal, translator.WithKey(resources.KeysInternalError).Translate(localizer))
	}

	return connect.NewResponse(&pb.ValidateUserResponse{
		UserId:      user.UserID,
		TokenType:   user.TokenType.String(),
		Permissions: mapPermissionsToProtoPermissions(permissionsSlice),
	}), nil
}

func (s *server) RevokeToken(ctx context.Context, req *connect.Request[pb.RevokeTokenRequest]) (*connect.Response[pb.RevokeTokenResponse], error) {
	localizer, ok := ctx.Value(translator.Key).(*translator.NebulaLocalizer)
	if !ok || localizer == nil {
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	user, ok := ctx.Value("user").(models.User)

	if !ok || user.TokenType == tokens.TokenTypeApplicationRequest {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Println("Cannot revoke user token: user is not authorized")
		}

		return nil, status.Errorf(
			codes.Unauthenticated,
			translator.WithKey(resources.KeysInvalidOrExpiredTokenError).Translate(localizer),
		)
	}

	validatedToken, tokenType := jwx.ValidateToken(req.Msg.GetToken())
	if validatedToken == nil || tokenType == nil || *tokenType == tokens.TokenTypeApplicationRequest {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Println("Cannot revoke user token: there was an error while parsing provided token")
		}

		return nil, status.Errorf(codes.Internal, translator.WithKey(resources.KeysProvidedTokenInvalidOrExpiredError).Translate(localizer))
	}

	requestedUserId := req.Msg.GetUserId()
	if utils.UtilString(requestedUserId).IsEmpty() {
		requestedUserId = user.UserID
	}

	isAdmin := user.HasPermission(permissions.AdminWritePermissionAction)

	if !isAdmin && (requestedUserId != user.UserID || user.UserID != validatedToken.Subject()) {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Printf("Cannot revoke user token: user %s does not have permissions to revoke provided token\n", user.UserID)
		}

		return nil, status.Errorf(
			codes.Internal,
			translator.WithKey(resources.KeysNotEnoughPermissions).Translate(localizer),
		)
	}

	err := s.services.TokensService.RevokeToken(req.Msg.GetToken())

	if err != nil {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Printf("Cannot revoke user token: %s\n", err.Error.Error())
		}

		return nil, status.Errorf(
			codes.Internal,
			translator.WithKey(resources.KeysNotEnoughPermissions).Translate(localizer),
		)
	}

	return connect.NewResponse(&pb.RevokeTokenResponse{
		IsSuccessful: true,
	}), nil
}

func (s *server) IsTokenRevoked(ctx context.Context, req *connect.Request[pb.IsTokenRevokedRequest]) (*connect.Response[pb.IsTokenRevokedResponse], error) {
	localizer, ok := ctx.Value(translator.Key).(*translator.NebulaLocalizer)
	if !ok || localizer == nil {
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	user, ok := ctx.Value("user").(models.User)

	if !ok || user.TokenType != tokens.TokenTypeApplicationRequest {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Println("Cannot check token revocation: user is not authorized")
		}

		return nil, status.Errorf(
			codes.Unauthenticated,
			translator.WithKey(resources.KeysInvalidOrExpiredTokenError).Translate(localizer),
		)
	}

	isRevoked := s.services.TokensService.IsTokenRevoked(req.Msg.GetToken())

	return connect.NewResponse(&pb.IsTokenRevokedResponse{
		IsRevoked: isRevoked,
	}), nil
}

func (s *server) GetKeySet(ctx context.Context, req *connect.Request[pb.GetKeySetRequest]) (*connect.Response[pb.GetKeySetResponse], error) {
	publicKey := jwx.CutcutfilmKeys.PublicKey

	if publicKey == nil {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Println("Cannot get keyset: public key not found")
		}

		return connect.NewResponse(&pb.GetKeySetResponse{}), nil
	}

	keySet := jwk.NewSet()
	_ = keySet.AddKey(*publicKey)

	jsonPubSet, err := json.Marshal(keySet)

	if err != nil {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Println("Cannot get keyset: cannot marshal keyset to JSON")
		}

		return connect.NewResponse(&pb.GetKeySetResponse{}), nil
	}

	encodedKeys := b64.StdEncoding.EncodeToString(jsonPubSet)

	return connect.NewResponse(&pb.GetKeySetResponse{
		EncodedKeys: encodedKeys,
	}), nil
}

func mapPermissionsToProtoPermissions(permissionsSlice []permissions.Permission) []*pb.Permission {
	var protoPermissions []*pb.Permission
	for _, permission := range permissionsSlice {
		if utils.UtilString(permission.Action).IsEmpty() {
			continue
		}

		permissionIndex := slices.IndexFunc(
			permissions.AllPermissions,
			func(p2 permissions.Permission) bool { return permission.Action == p2.Action },
		)

		if permissionIndex < 0 {
			continue
		}

		protoPermissions = append(protoPermissions, &pb.Permission{
			Action:      permissions.AllPermissions[permissionIndex].Action,
			Description: permissions.AllPermissions[permissionIndex].Description,
		})
	}

	return protoPermissions
}

func mapProtoPermissionsToPermissions(permissionsSlice []*pb.Permission) []permissions.Permission {
	if permissionsSlice == nil {
		return []permissions.Permission{}
	}

	var corePermissions []permissions.Permission
	for _, permission := range permissionsSlice {
		if utils.UtilString(permission.GetAction()).IsEmpty() {
			continue
		}

		permissionIndex := slices.IndexFunc(
			permissions.AllPermissions,
			func(p2 permissions.Permission) bool { return permission.GetAction() == p2.Action },
		)

		if permissionIndex < 0 {
			continue
		}

		corePermissions = append(corePermissions, permissions.Permission{
			Action:      permissions.AllPermissions[permissionIndex].Action,
			Description: permissions.AllPermissions[permissionIndex].Description,
		})
	}

	return corePermissions
}

func mapStringPermissionsToPermissions(permissionsSlice []string) []permissions.Permission {
	if permissionsSlice == nil {
		return []permissions.Permission{}
	}

	var corePermissions []permissions.Permission
	for _, permission := range permissionsSlice {
		if utils.UtilString(permission).IsEmpty() {
			continue
		}

		permissionIndex := slices.IndexFunc(
			permissions.AllPermissions,
			func(p2 permissions.Permission) bool { return permission == p2.Action },
		)

		if permissionIndex < 0 {
			continue
		}

		corePermissions = append(corePermissions, permissions.Permission{
			Action:      permissions.AllPermissions[permissionIndex].Action,
			Description: permissions.AllPermissions[permissionIndex].Description,
		})
	}

	return corePermissions
}
