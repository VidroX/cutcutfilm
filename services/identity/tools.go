//go:build tools
// +build tools

package tools

import (
	_ "github.com/VidroX/cutcutfilm-shared/translator"
	_ "github.com/VidroX/cutcutfilm-shared/utils"
	_ "github.com/go-playground/validator/v10"
	_ "github.com/joho/godotenv"
	_ "google.golang.org/grpc"
	_ "gorm.io/driver/postgres"
	_ "gorm.io/gorm"
)
