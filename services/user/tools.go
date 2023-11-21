//go:build tools
// +build tools

package tools

import (
	_ "github.com/99designs/gqlgen"
	_ "github.com/99designs/gqlgen/graphql/introspection"
	_ "github.com/VidroX/cutcutfilm-shared"
	_ "github.com/VidroX/cutcutfilm-shared/errors"
	_ "github.com/VidroX/cutcutfilm-shared/utils"
	_ "github.com/alexedwards/argon2id"
	_ "github.com/go-playground/validator/v10"
	_ "github.com/jackc/pgerrcode"
	_ "github.com/joho/godotenv"
	_ "gorm.io/driver/postgres"
	_ "gorm.io/gorm"
)
