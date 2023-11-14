package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/VidroX/cutcutfilm/services/identity/core/database"
	"github.com/VidroX/cutcutfilm/services/identity/core/repositories"
	"github.com/VidroX/cutcutfilm/services/identity/core/services"

	"github.com/VidroX/cutcutfilm/services/identity/resources"

	"github.com/VidroX/cutcutfilm-shared/translator"
	"github.com/VidroX/cutcutfilm/services/identity/core/environment"
	"github.com/VidroX/cutcutfilm/services/identity/core/jwx"
	pb "github.com/VidroX/cutcutfilm/services/identity/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

const defaultPort = "4002"

type server struct {
	pb.UnimplementedIdentityServer
	repositories *repositories.Repositories
	services     *services.Services
}

func main() {
	environment.LoadEnvironment(nil)

	debug := strings.EqualFold(os.Getenv(environment.KeysDebug), "True")

	private, public := jwx.InitKeySet()

	jwx.CutcutfilmKeys = &jwx.Keys{
		PrivateKey: &private,
		PublicKey:  &public,
	}

	db := initDatabase()
	initServer(debug, db)
}

func initDatabase() *database.NebulaDb {
	gormDB := database.Init()

	gormDB.AutoMigrateAll()
	gormDB.PopulatePermissions()
	gormDB.SetAdminPermissions()

	return gormDB
}

func initServer(debug bool, db *database.NebulaDb) {
	port := os.Getenv(environment.KeysPort)

	if port == "" {
		port = defaultPort
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", port))

	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer(
		grpc.UnaryInterceptor(serverInterceptor),
	)

	repos := repositories.Init(&repositories.RepositoryDependencies{Database: db})
	pb.RegisterIdentityServer(s, &server{
		repositories: repos,
		services:     services.Init(&services.ServiceDependencies{Repositories: repos}),
	})

	if debug {
		reflection.Register(s)
	}

	log.Printf("server listening at %v", lis.Addr())

	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func serverInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)

	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "Retrieving metadata has failed")
	}

	ctx, err := environmentInterceptor(ctx, md)

	if err != nil {
		return nil, err
	}

	ctx, err = authInterceptor(ctx, md)

	if err != nil {
		return nil, err
	}

	return handler(ctx, req)
}

func environmentInterceptor(ctx context.Context, md metadata.MD) (context.Context, error) {
	lang, ok := md["accept-language"]
	normalizedLang := "en"
	if ok && len(lang) >= 0 {
		normalizedLang = lang[0]
	}

	nebulaLocalizer := translator.Init(
		[]string{
			os.Getenv(environment.KeysAppPath) + "/resources/i18n/en.json",
		},
		normalizedLang,
	)

	ctx = context.WithValue(ctx, translator.Key, &nebulaLocalizer)

	return ctx, nil
}

func authInterceptor(ctx context.Context, md metadata.MD) (context.Context, error) {
	localizer, ok := ctx.Value(translator.Key).(*translator.NebulaLocalizer)
	if !ok {
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	apiKey, ok := md["x-api-key"]
	if !ok || apiKey[0] != os.Getenv(environment.KeysAPIKey) {
		return nil, status.Errorf(
			codes.Unauthenticated,
			translator.
				WithKey(resources.KeysInvalidOrExpiredTokenError).
				Translate(localizer),
		)
	}

	authToken, ok := md["authorization"]
	if !ok {
		return nil, status.Errorf(
			codes.Unauthenticated,
			translator.
				WithKey(resources.KeysInvalidOrExpiredTokenError).
				Translate(localizer),
		)
	}

	searchRegex := regexp.MustCompile("(?i)" + "Bearer")
	token := strings.TrimSpace(searchRegex.ReplaceAllString(authToken[0], ""))

	validatedToken, tokenType := jwx.ValidateToken(token)

	if validatedToken == nil || tokenType == nil {
		return nil, status.Errorf(
			codes.Unauthenticated,
			translator.
				WithKey(resources.KeysInvalidOrExpiredTokenError).
				Translate(localizer),
		)
	}

	userId, exists := validatedToken.Get("sub")

	if !exists {
		return nil, status.Errorf(
			codes.Unauthenticated,
			translator.
				WithKey(resources.KeysInvalidOrExpiredTokenError).
				Translate(localizer),
		)
	}

	ctx = context.WithValue(ctx, "user_id", userId.(string))
	ctx = context.WithValue(ctx, "user_token_type", tokenType)

	return ctx, nil
}
