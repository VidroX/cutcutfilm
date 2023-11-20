//go:build tools
// +build tools

package tools

import (
	_ "connectrpc.com/connect"
	_ "connectrpc.com/grpcreflect"
	_ "github.com/VidroX/cutcutfilm-shared/errors"
	_ "github.com/VidroX/cutcutfilm-shared/permissions"
	_ "github.com/VidroX/cutcutfilm-shared/translator"
	_ "github.com/VidroX/cutcutfilm-shared/utils"
	_ "github.com/emirpasic/gods/sets/hashset"
	_ "github.com/google/uuid"
	_ "github.com/jackc/pgerrcode"
	_ "github.com/jackc/pgx/v5/pgconn"
	_ "github.com/joho/godotenv"
	_ "google.golang.org/grpc"
	_ "gorm.io/driver/postgres"
	_ "gorm.io/gorm"
)
