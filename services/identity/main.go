package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"connectrpc.com/grpcreflect"
	"github.com/VidroX/cutcutfilm-shared/utils"

	"connectrpc.com/connect"
	"github.com/VidroX/cutcutfilm/services/identity/core/database"
	"github.com/VidroX/cutcutfilm/services/identity/core/repositories"
	"github.com/VidroX/cutcutfilm/services/identity/core/services"
	"github.com/google/uuid"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/VidroX/cutcutfilm/services/identity/resources"

	"github.com/VidroX/cutcutfilm-shared/permissions"
	"github.com/VidroX/cutcutfilm-shared/translator"
	"github.com/VidroX/cutcutfilm/services/identity/core/environment"
	"github.com/VidroX/cutcutfilm/services/identity/core/jwx"
	"github.com/VidroX/cutcutfilm/services/identity/proto/identity/v1/identityv1connect"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const defaultPort = "4002"

type server struct {
	identityv1connect.UnimplementedIdentityServiceHandler
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

	mux := http.NewServeMux()
	address := fmt.Sprintf(":%s", port)

	repos := repositories.Init(&repositories.RepositoryDependencies{Database: db})
	path, handler := identityv1connect.NewIdentityServiceHandler(
		&server{
			repositories: repos,
			services:     services.Init(&services.ServiceDependencies{Repositories: repos}),
		},
		connect.WithInterceptors(
			connect.UnaryInterceptorFunc(serverInterceptor),
		),
	)

	mux.Handle(path, handler)

	if debug {
		reflector := grpcreflect.NewStaticReflector(
			"identity.v1.IdentityService",
		)
		mux.Handle(grpcreflect.NewHandlerV1(reflector))
		mux.Handle(grpcreflect.NewHandlerV1Alpha(reflector))
	}

	fmt.Println("... Listening on", address)
	err := http.ListenAndServe(address, h2c.NewHandler(mux, &http2.Server{}))

	if err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func serverInterceptor(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
		ctx, err := environmentInterceptor(ctx, request.Header())

		if err != nil {
			return nil, err
		}

		ctx, err = authInterceptor(ctx, request.Header())

		if err != nil {
			return nil, err
		}

		return next(ctx, request)
	}
}

func environmentInterceptor(ctx context.Context, headers http.Header) (context.Context, error) {
	lang := headers.Get("accept-language")
	normalizedLang := "en"
	if len(lang) >= 0 {
		normalizedLang = lang
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

func authInterceptor(ctx context.Context, headers http.Header) (context.Context, error) {
	localizer, ok := ctx.Value(translator.Key).(*translator.NebulaLocalizer)
	if !ok {
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	if headers.Get("x-api-key") != os.Getenv(environment.KeysAPIKey) {
		return nil, status.Errorf(
			codes.Unauthenticated,
			translator.
				WithKey(resources.KeysInvalidOrExpiredTokenError).
				Translate(localizer),
		)
	}

	authToken := headers.Get("authorization")
	if utils.UtilString(authToken).IsEmpty() {
		return nil, status.Errorf(
			codes.Unauthenticated,
			translator.
				WithKey(resources.KeysInvalidOrExpiredTokenError).
				Translate(localizer),
		)
	}

	searchRegex := regexp.MustCompile("(?i)" + "Bearer")
	token := strings.TrimSpace(searchRegex.ReplaceAllString(authToken, ""))

	validatedToken, tokenType := jwx.ValidateToken(token)

	if validatedToken == nil || tokenType == nil {
		return nil, status.Errorf(
			codes.Unauthenticated,
			translator.
				WithKey(resources.KeysInvalidOrExpiredTokenError).
				Translate(localizer),
		)
	}

	if *tokenType != jwx.TokenTypeApplicationRequest {
		userId, exists := validatedToken.Get("sub")

		if !exists {
			return nil, status.Errorf(
				codes.Unauthenticated,
				translator.
					WithKey(resources.KeysInvalidOrExpiredTokenError).
					Translate(localizer),
			)
		}

		_, err := uuid.Parse(userId.(string))

		if err != nil {
			return nil, status.Errorf(
				codes.Unauthenticated,
				translator.
					WithKey(resources.KeysInvalidOrExpiredTokenError).
					Translate(localizer),
			)
		}

		ctx = context.WithValue(ctx, "user_id", userId.(string))
	}

	issuer, exists := validatedToken.Get("iss")

	if !exists {
		return nil, status.Errorf(
			codes.Unauthenticated,
			translator.
				WithKey(resources.KeysInvalidOrExpiredTokenError).
				Translate(localizer),
		)
	}

	permissionsString, exists := validatedToken.Get("permissions")
	if !exists {
		permissionsString = ""
	}

	ctx = context.WithValue(ctx, "user_token_type", tokenType)
	ctx = context.WithValue(ctx, "user_token_issuer", issuer.(string))
	ctx = context.WithValue(ctx, "user_permissions", permissions.ParsePermissionsString(permissionsString.(string)))

	return ctx, nil
}
