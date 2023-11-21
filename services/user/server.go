package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
	cutcutfilm "github.com/VidroX/cutcutfilm-shared"
	"github.com/VidroX/cutcutfilm-shared/config"
	"github.com/VidroX/cutcutfilm-shared/directives"
	"github.com/VidroX/cutcutfilm-shared/jwx"
	"github.com/VidroX/cutcutfilm-shared/translator"
	"github.com/VidroX/cutcutfilm/services/user/core/database"
	"github.com/VidroX/cutcutfilm/services/user/core/environment"
	"github.com/VidroX/cutcutfilm/services/user/core/errors/general"
	"github.com/VidroX/cutcutfilm/services/user/core/repositories"
	"github.com/VidroX/cutcutfilm/services/user/core/services"
	"github.com/VidroX/cutcutfilm/services/user/graph"
	resolvers "github.com/VidroX/cutcutfilm/services/user/graph/resolvers"
)

const defaultPort = "4001"

var directivesList = graph.DirectiveRoot{
	IsAuthenticated: directives.IsAuthenticatedDirective,
	HasPermission:   directives.HasPermissionDirective,
}

func initDatabase() *database.NebulaDb {
	gormDB := database.Init()

	gormDB.AutoMigrateAll()
	gormDB.CreateAdminUser()

	return gormDB
}

func main() {
	environment.LoadEnvironment(nil)

	port := os.Getenv(environment.KeysPort)
	debug := os.Getenv(environment.KeysDebug) == "True"

	if port == "" {
		port = defaultPort
	}

	cutcutfilm.Init(&config.CutcutfilmConfig{
		Debug:           debug,
		DataPath:        os.Getenv(environment.KeysDataPath),
		EnvironmentType: os.Getenv(environment.KeysEnvironmentType),
		JWTIssuer:       os.Getenv(environment.KeysTokenIssuer),
		JWTAudiences: []string{
			os.Getenv(environment.KeysIdentityServiceLocation),
		},
		AllowedJWTIssuers: []string{
			os.Getenv(environment.KeysIdentityServiceLocation),
		},
	})

	db := initDatabase()

	repos := repositories.Init(&repositories.RepositoryDependencies{
		Database: db,
	})

	srv := handler.NewDefaultServer(
		graph.NewExecutableSchema(
			graph.Config{
				Resolvers: &resolvers.Resolver{
					Services: services.Init(&services.ServiceDependencies{
						Repositories: repos,
					}),
				},
				Directives: directivesList,
			},
		),
	)

	if debug {
		http.Handle("/", playground.Handler("GraphQL Playground", "/gql"))
	}

	http.Handle("/gql", localizerMiddleware(authMiddleware(srv)))

	if debug {
		log.Printf("Server ready at http://localhost:%s/gql. GraphQL Playground available at http://localhost:%s", port, port)
	} else {
		log.Printf("Server ready at http://localhost:%s/gql", port)
	}

	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func localizerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lang := r.Header.Get("accept-language")
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

		config.SetErrorTranslation("noPermissions", config.ErrorDetails{
			Code: general.ErrNotEnoughPermissions.Code,
			Message: translator.
				WithKey(general.ErrNotEnoughPermissions.Error.Error()).
				Translate(&nebulaLocalizer),
		})

		ctx := r.Context()
		ctx = context.WithValue(ctx, translator.Key, &nebulaLocalizer)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("authorization")
		user := jwx.ValidateIdentityToken(token)

		if user != nil {
			ctx := r.Context()
			ctx = context.WithValue(ctx, "user", user)

			next.ServeHTTP(w, r.WithContext(ctx))

			return
		}

		next.ServeHTTP(w, r)
	})
}
