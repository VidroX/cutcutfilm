package main

import (
	"log"
	"net/http"
	"os"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/VidroX/cutcutfilm/services/user/graph"
	resolvers "github.com/VidroX/cutcutfilm/services/user/graph/resolvers"
)

const defaultPort = "8080"

func main() {
	port := os.Getenv("PORT")
	debug := os.Getenv("DEBUG") == "true"
	
	if port == "" {
		port = defaultPort
	}

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
