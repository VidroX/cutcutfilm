package main

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	b64 "encoding/base64"

	"connectrpc.com/connect"
	nebulaErrors "github.com/VidroX/cutcutfilm-shared/errors"
	"github.com/VidroX/cutcutfilm-shared/permissions"
	"github.com/VidroX/cutcutfilm-shared/tokens"
	"github.com/VidroX/cutcutfilm-shared/translator"
	"github.com/VidroX/cutcutfilm-shared/utils"
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

	isAuthorized, ok := ctx.Value("authorized").(bool)
	userTokenType, ok2 := ctx.Value("user_token_type").(*tokens.TokenType)

	if !ok || !isAuthorized || !ok2 || userTokenType == nil || *userTokenType != tokens.TokenTypeApplicationRequest {
		return nil, status.Errorf(
			codes.Unauthenticated,
			translator.WithKey(resources.KeysInvalidOrExpiredTokenError).Translate(localizer),
		)
	}

	userId := req.Msg.GetUserId()
	_, err := uuid.Parse(userId)

	if utils.UtilString(userId).IsEmpty() || err != nil {
		return nil, status.Errorf(codes.Internal, translator.WithKey(resources.KeysUserRequiredError).Translate(localizer))
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

	isAuthorized, ok := ctx.Value("authorized").(bool)
	userId, ok2 := ctx.Value("user_id").(string)
	userTokenType, ok3 := ctx.Value("user_token_type").(*tokens.TokenType)

	if !ok || !isAuthorized || !ok2 || !ok3 || userTokenType == nil || *userTokenType == tokens.TokenTypeApplicationRequest {
		return nil, status.Errorf(
			codes.Unauthenticated,
			translator.WithKey(resources.KeysInvalidOrExpiredTokenError).Translate(localizer),
		)
	}

	_, err := uuid.Parse(userId)

	if utils.UtilString(userId).IsEmpty() || err != nil {
		return nil, status.Errorf(codes.Internal, translator.WithKey(resources.KeysUserRequiredError).Translate(localizer))
	}

	permissionsSlice, err2 := s.services.PermissionsService.GetOrSetDefaultUserPermissions(userId)

	if err2 != nil {
		return nil, status.Errorf(codes.Internal, translator.WithKey(resources.KeysInternalError).Translate(localizer))
	}

	return connect.NewResponse(&pb.IssueServiceTokenResponse{
		Token: jwx.CreateToken(&jwx.TokenParams{
			TokenType:   *userTokenType,
			UserId:      &userId,
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

	isAuthorized, ok := ctx.Value("authorized").(bool)
	userId, ok2 := ctx.Value("user_id").(string)
	userTokenType, ok3 := ctx.Value("user_token_type").(*tokens.TokenType)

	if !ok || !isAuthorized || !ok2 || !ok3 || userTokenType == nil || *userTokenType != tokens.TokenTypeRefresh {
		return nil, status.Errorf(
			codes.Unauthenticated,
			translator.WithKey(resources.KeysInvalidOrExpiredTokenError).Translate(localizer),
		)
	}

	permissionsSlice, err := s.services.PermissionsService.GetOrSetDefaultUserPermissions(userId)

	if err != nil {
		return nil, status.Errorf(codes.Internal, translator.WithKey(resources.KeysInternalError).Translate(localizer))
	}

	return connect.NewResponse(&pb.RefreshTokenResponse{
		Token: jwx.CreateToken(&jwx.TokenParams{
			TokenType:   tokens.TokenTypeAccess,
			UserId:      &userId,
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

	isAuthorized, ok := ctx.Value("authorized").(bool)
	userId, ok2 := ctx.Value("user_id").(string)
	userTokenType, ok3 := ctx.Value("user_token_type").(*tokens.TokenType)
	userPermissions, ok4 := ctx.Value("user_permissions").([]permissions.Permission)

	if !ok || !isAuthorized || !ok2 || !ok3 || !ok4 || userPermissions == nil || userTokenType == nil || *userTokenType != tokens.TokenTypeAccess {
		return nil, status.Errorf(
			codes.Unauthenticated,
			translator.WithKey(resources.KeysInvalidOrExpiredTokenError).Translate(localizer),
		)
	}

	permissionsSlice := mapStringPermissionsToPermissions(req.Msg.GetPermissions())

	requestedUserId := req.Msg.GetUserId()
	if utils.UtilString(requestedUserId).IsEmpty() {
		requestedUserId = userId
	}

	isAdmin := slices.ContainsFunc(
		userPermissions,
		func(p permissions.Permission) bool { return p.Action == "write:admin" },
	)

	if !isAdmin {
		return nil, status.Errorf(
			codes.Internal,
			translator.WithKey(resources.KeysNotEnoughPermissions).Translate(localizer),
		)
	}

	if requestedUserId == userId {
		hasAdminWritePermission := slices.ContainsFunc(
			permissionsSlice,
			func(p permissions.Permission) bool { return p.Action == "write:admin" },
		)
		hasAdminReadPermission := slices.ContainsFunc(
			permissionsSlice,
			func(p permissions.Permission) bool { return p.Action == "read:admin" },
		)

		if !hasAdminReadPermission || !hasAdminWritePermission {
			return nil, status.Errorf(
				codes.Internal,
				translator.WithKey(resources.KeysNotEnoughPermissions).Translate(localizer),
			)
		}
	}

	err := s.services.PermissionsService.SetUserPermissions(requestedUserId, permissionsSlice)

	if err != nil {
		return nil, status.Errorf(codes.Internal, translator.WithKey(resources.KeysInternalError).Translate(localizer))
	}

	user := &pb.UserWithPermissions{
		UserId:      requestedUserId,
		Permissions: mapPermissionsToProtoPermissions(permissionsSlice),
	}

	return connect.NewResponse(&pb.SetUserPermissionsResponse{
		Token: jwx.CreateToken(&jwx.TokenParams{
			TokenType:   *userTokenType,
			UserId:      &requestedUserId,
			Permissions: permissionsSlice,
			AddAudience: true,
		}),
		User: user,
	}), nil
}

func (s *server) GetUserPermissions(ctx context.Context, req *connect.Request[pb.GetUserPermissionsRequest]) (*connect.Response[pb.GetUserPermissionsResponse], error) {
	localizer, ok := ctx.Value(translator.Key).(*translator.NebulaLocalizer)
	if !ok || localizer == nil {
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	isAuthorized, ok := ctx.Value("authorized").(bool)
	userId, ok2 := ctx.Value("user_id").(string)
	userTokenType, ok3 := ctx.Value("user_token_type").(*tokens.TokenType)
	userPermissions, _ := ctx.Value("user_permissions").([]permissions.Permission)

	if !ok || !isAuthorized || !ok2 || !ok3 || userTokenType == nil || *userTokenType != tokens.TokenTypeAccess {
		return nil, status.Errorf(
			codes.Unauthenticated,
			translator.WithKey(resources.KeysInvalidOrExpiredTokenError).Translate(localizer),
		)
	}

	requestedUserId := req.Msg.GetUserId()
	if utils.UtilString(requestedUserId).IsEmpty() {
		requestedUserId = userId
	}

	isAdmin := slices.ContainsFunc(
		userPermissions,
		func(p permissions.Permission) bool { return p.Action == "read:admin" },
	)

	if !isAdmin && requestedUserId != userId {
		return nil, status.Errorf(
			codes.Internal,
			translator.WithKey(resources.KeysNotEnoughPermissions).Translate(localizer),
		)
	}

	var permissionsSlice []permissions.Permission
	var err *nebulaErrors.APIError

	if requestedUserId == userId {
		permissionsSlice, err = s.services.PermissionsService.GetOrSetDefaultUserPermissions(requestedUserId)
	} else {
		permissionsSlice, err = s.services.PermissionsService.GetUserPermissions(requestedUserId)
	}

	if err != nil {
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

	isAuthorized, ok := ctx.Value("authorized").(bool)
	userId, ok2 := ctx.Value("user_id").(string)
	userTokenType, ok3 := ctx.Value("user_token_type").(*tokens.TokenType)

	if !ok || !isAuthorized || !ok2 || !ok3 || userTokenType == nil {
		return nil, status.Errorf(
			codes.Unauthenticated,
			translator.WithKey(resources.KeysInvalidOrExpiredTokenError).Translate(localizer),
		)
	}

	var permissionsSlice []permissions.Permission
	var err *nebulaErrors.APIError

	permissionsSlice, err = s.services.PermissionsService.GetOrSetDefaultUserPermissions(userId)

	if err != nil {
		return nil, status.Errorf(codes.Internal, translator.WithKey(resources.KeysInternalError).Translate(localizer))
	}

	return connect.NewResponse(&pb.ValidateUserResponse{
		UserId:      userId,
		TokenType:   userTokenType.String(),
		Permissions: mapPermissionsToProtoPermissions(permissionsSlice),
	}), nil
}

func (s *server) GetKeySet(ctx context.Context, req *connect.Request[pb.GetKeySetRequest]) (*connect.Response[pb.GetKeySetResponse], error) {
	publicKey := jwx.CutcutfilmKeys.PublicKey

	if publicKey == nil {
		return connect.NewResponse(&pb.GetKeySetResponse{}), nil
	}

	keySet := jwk.NewSet()
	_ = keySet.AddKey(*publicKey)

	jsonPubSet, err := json.Marshal(keySet)

	if err != nil {
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
