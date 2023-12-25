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
	"github.com/VidroX/cutcutfilm-shared/contextuser"
	"github.com/VidroX/cutcutfilm-shared/tokens"
	"github.com/VidroX/cutcutfilm-shared/utils"

	"connectrpc.com/connect"
	"github.com/VidroX/cutcutfilm/services/identity/core/database"
	"github.com/VidroX/cutcutfilm/services/identity/core/database/models"
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

	if debug {
		log.Printf("Storage mounted at: %s\n", os.Getenv(environment.KeysDataPath))
	}

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
	serverInit := &server{
		repositories: repos,
		services:     services.Init(&services.ServiceDependencies{Repositories: repos}),
	}
	path, handler := identityv1connect.NewIdentityServiceHandler(
		serverInit,
		connect.WithInterceptors(
			connect.UnaryInterceptorFunc(serverInit.serverInterceptor),
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

func (core *server) serverInterceptor(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
		if core == nil {
			return nil, fmt.Errorf("Cannot retrieve core instance")
		}

		ctx, err := environmentInterceptor(ctx, request.Header())

		if err != nil {
			return nil, err
		}

		ctx, err = authInterceptor(ctx, core, request.Header())

		if err != nil {
			return nil, err
		}

		return next(ctx, request)
	}
}

func environmentInterceptor(ctx context.Context, headers http.Header) (context.Context, error) {
	lang := headers.Get("accept-language")
	normalizedLang := "en"
	if len(lang) > 0 {
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

func authInterceptor(ctx context.Context, core *server, headers http.Header) (context.Context, error) {
	localizer, ok := ctx.Value(translator.Key).(*translator.NebulaLocalizer)
	if !ok {
		return nil, status.Errorf(codes.Internal, "Internal server error")
	}

	if headers.Get("x-api-key") != os.Getenv(environment.KeysAPIKey) {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Println("Provided x-api-key does not match")
		}

		return nil, status.Errorf(
			codes.Unauthenticated,
			translator.
				WithKey(resources.KeysInvalidOrExpiredTokenError).
				Translate(localizer),
		)
	}

	authToken := headers.Get("authorization")
	if utils.UtilString(authToken).IsEmpty() {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Println("Provided auth token is empty")
		}

		return ctx, nil
	}

	searchRegex := regexp.MustCompile("(?i)" + "Bearer")
	token := strings.TrimSpace(searchRegex.ReplaceAllString(authToken, ""))

	validatedToken, tokenType := jwx.ValidateToken(token)

	if validatedToken == nil || tokenType == nil {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Println("Could not validate user token")
		}

		return nil, status.Errorf(
			codes.Unauthenticated,
			translator.
				WithKey(resources.KeysInvalidOrExpiredTokenError).
				Translate(localizer),
		)
	}

	isRevoked := core.services.TokensService.IsTokenRevoked(token)

	if isRevoked {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Println("Provided token is revoked")
		}

		return nil, status.Errorf(
			codes.Unauthenticated,
			translator.
				WithKey(resources.KeysInvalidOrExpiredTokenError).
				Translate(localizer),
		)
	}

	var userId string
	if *tokenType != tokens.TokenTypeApplicationRequest {
		sub, exists := validatedToken.Get("sub")

		if !exists {
			if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
				log.Println("Provided user token does not have sub claim")
			}

			return nil, status.Errorf(
				codes.Unauthenticated,
				translator.
					WithKey(resources.KeysInvalidOrExpiredTokenError).
					Translate(localizer),
			)
		}

		_, err := uuid.Parse(sub.(string))

		if err != nil {
			return nil, status.Errorf(
				codes.Unauthenticated,
				translator.
					WithKey(resources.KeysInvalidOrExpiredTokenError).
					Translate(localizer),
			)
		}

		userId = sub.(string)

		ctx = context.WithValue(ctx, "user", models.User{
			ContextUser: contextuser.ContextUser{
				UserID: userId,
			},
		})
	}

	issuer, exists := validatedToken.Get("iss")

	if !exists {
		if strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
			log.Println("Provided user token does not have iss claim")
		}

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

	ctx = context.WithValue(ctx, "user", models.User{
		ContextUser: contextuser.ContextUser{
			UserID:      userId,
			TokenType:   *tokenType,
			Permissions: permissions.ParsePermissionsString(permissionsString.(string)),
		},
		TokenIssuer: issuer.(string),
	})

	return ctx, nil
}
