package main

import (
	"context"
	"slices"

	nebulaErrors "github.com/VidroX/cutcutfilm-shared/errors"
	"github.com/VidroX/cutcutfilm-shared/permissions"
	"github.com/VidroX/cutcutfilm-shared/translator"
	"github.com/VidroX/cutcutfilm-shared/utils"
	"github.com/VidroX/cutcutfilm/services/identity/core/jwx"
	pb "github.com/VidroX/cutcutfilm/services/identity/identity"
	"github.com/VidroX/cutcutfilm/services/identity/resources"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *server) IssueTokens(ctx context.Context, in *pb.IssueTokensRequest) (*pb.MultipleTokensReply, error) {
	localizer, ok := ctx.Value(translator.Key).(*translator.NebulaLocalizer)
	if !ok || localizer == nil {
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	userTokenType, ok2 := ctx.Value("user_token_type").(*jwx.TokenType)

	if !ok2 || userTokenType == nil || *userTokenType != jwx.TokenTypeApplicationRequest {
		return nil, status.Errorf(
			codes.Internal,
			translator.WithKey(resources.KeysInvalidOrExpiredTokenError).Translate(localizer),
		)
	}

	userId := in.GetUserId()
	_, err := uuid.Parse(userId)

	if utils.UtilString(userId).IsEmpty() || err != nil {
		return nil, status.Errorf(codes.Internal, translator.WithKey(resources.KeysUserRequiredError).Translate(localizer))
	}

	permissionsSlice, err2 := s.services.PermissionsService.GetOrSetDefaultUserPermissions(userId)

	if err2 != nil {
		return nil, status.Errorf(codes.Internal, translator.WithKey(resources.KeysInternalError).Translate(localizer))
	}

	return &pb.MultipleTokensReply{
		AccessToken:  jwx.CreateToken(jwx.TokenTypeAccess, &userId, permissionsSlice),
		RefreshToken: jwx.CreateToken(jwx.TokenTypeRefresh, &userId, nil),
	}, nil
}

func (s *server) RefreshToken(ctx context.Context, in *pb.TokenRequest) (*pb.TokenReply, error) {
	localizer, ok := ctx.Value(translator.Key).(*translator.NebulaLocalizer)
	if !ok || localizer == nil {
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	userId, ok := ctx.Value("user_id").(string)
	userTokenType, ok2 := ctx.Value("user_token_type").(*jwx.TokenType)

	if !ok || !ok2 || userTokenType == nil || *userTokenType != jwx.TokenTypeRefresh {
		return nil, status.Errorf(
			codes.Internal,
			translator.WithKey(resources.KeysInvalidOrExpiredTokenError).Translate(localizer),
		)
	}

	permissionsSlice, err := s.services.PermissionsService.GetOrSetDefaultUserPermissions(userId)

	if err != nil {
		return nil, status.Errorf(codes.Internal, translator.WithKey(resources.KeysInternalError).Translate(localizer))
	}

	return &pb.TokenReply{Token: jwx.CreateToken(jwx.TokenTypeAccess, &userId, permissionsSlice)}, nil
}

func (s *server) SetUserPermissions(ctx context.Context, in *pb.SetUserPermissionsRequest) (*pb.SetUserPermissionsReply, error) {
	localizer, ok := ctx.Value(translator.Key).(*translator.NebulaLocalizer)
	if !ok || localizer == nil {
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	userId, ok := ctx.Value("user_id").(string)
	userTokenType, ok2 := ctx.Value("user_token_type").(*jwx.TokenType)
	userPermissions, ok3 := ctx.Value("user_permissions").([]permissions.Permission)

	if !ok || !ok2 || !ok3 || userPermissions == nil || userTokenType == nil || *userTokenType != jwx.TokenTypeAccess {
		return nil, status.Errorf(
			codes.Internal,
			translator.WithKey(resources.KeysInvalidOrExpiredTokenError).Translate(localizer),
		)
	}

	permissionsSlice := mapStringPermissionsToPermissions(in.GetPermissions())

	requestedUserId := in.GetUserId()
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

	return &pb.SetUserPermissionsReply{
		Token: jwx.CreateToken(*userTokenType, &requestedUserId, permissionsSlice),
		User:  user,
	}, nil
}

func (s *server) GetUserPermissions(ctx context.Context, in *pb.GetUserPermissionsRequest) (*pb.UserWithPermissions, error) {
	localizer, ok := ctx.Value(translator.Key).(*translator.NebulaLocalizer)
	if !ok || localizer == nil {
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	userId, ok := ctx.Value("user_id").(string)
	userTokenType, ok2 := ctx.Value("user_token_type").(*jwx.TokenType)
	userPermissions, _ := ctx.Value("user_permissions").([]permissions.Permission)

	if !ok || !ok2 || userTokenType == nil || *userTokenType != jwx.TokenTypeAccess {
		return nil, status.Errorf(
			codes.Internal,
			translator.WithKey(resources.KeysInvalidOrExpiredTokenError).Translate(localizer),
		)
	}

	requestedUserId := in.GetUserId()
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

	return &pb.UserWithPermissions{
		UserId:      requestedUserId,
		Permissions: mapPermissionsToProtoPermissions(permissionsSlice),
	}, nil
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
