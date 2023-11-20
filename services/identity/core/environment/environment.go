package environment

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"
)

type EnvironmentParams struct {
	BasePath string
}

func LoadEnvironment(params *EnvironmentParams) {
	if params == nil {
		params = &EnvironmentParams{
			BasePath: "",
		}
	}

	var err error = nil
	var envName string

	envName = ".env"
	err = godotenv.Load(params.BasePath + envName)

	if err != nil {
		log.Printf("Error loading .env file (%s)", envName)
	}

	var path string

	if len(strings.TrimSpace(params.BasePath)) == 0 {
		path, err = filepath.Abs("./")
	} else {
		path, err = filepath.Abs(params.BasePath + "/")
	}

	if err == nil {
		_ = os.Setenv(KeysAppPath, path)
	}
}
