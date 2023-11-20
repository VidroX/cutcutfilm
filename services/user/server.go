package main

import (
	"log"
	"net/http"
	"os"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
	cutcutfilm "github.com/VidroX/cutcutfilm-shared"
	"github.com/VidroX/cutcutfilm-shared/config"
	"github.com/VidroX/cutcutfilm/services/user/environment"
	"github.com/VidroX/cutcutfilm/services/user/graph"
	resolvers "github.com/VidroX/cutcutfilm/services/user/graph/resolvers"
)

const defaultPort = "4001"

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
	})

	srv := handler.NewDefaultServer(graph.NewExecutableSchema(graph.Config{Resolvers: &resolvers.Resolver{}}))

	if debug {
		http.Handle("/", playground.Handler("GraphQL Playground", "/gql"))
	}

	http.Handle("/gql", srv)

	if debug {
		log.Printf("Server ready at http://localhost:%s/gql. GraphQL Playground available at http://localhost:%s", port, port)
	} else {
		log.Printf("Server ready at http://localhost:%s/gql", port)
	}

	log.Fatal(http.ListenAndServe(":"+port, nil))
}
