package main

import (
	"context"
	"github.com/VidroX/cutcutfilm-shared/translator"
	"github.com/VidroX/cutcutfilm/services/identity/core/jwx"
	pb "github.com/VidroX/cutcutfilm/services/identity/identity"
	"github.com/VidroX/cutcutfilm/services/identity/resources"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *server) IssueToken(ctx context.Context, in *pb.TokenRequest) (*pb.TokenReply, error) {
	localizer, ok := ctx.Value(translator.Key).(*translator.NebulaLocalizer)
	if !ok || localizer == nil {
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	userId, ok := ctx.Value("user_id").(string)
	userTokenType, ok2 := ctx.Value("user_token_type").(*jwx.TokenType)

	if !ok || !ok2 || userTokenType == nil {
		return nil, status.Errorf(codes.Internal, translator.WithKey(resources.KeysInternalError).Translate(localizer))
	}

	permissions, err := s.services.PermissionsService.GetUserPermissions(userId)

	if err != nil {
		return nil, status.Errorf(codes.Internal, translator.WithKey(resources.KeysInternalError).Translate(localizer))
	}

	return &pb.TokenReply{Token: jwx.CreateToken(*userTokenType, userId, permissions)}, nil
}
