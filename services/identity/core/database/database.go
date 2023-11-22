package database

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/VidroX/cutcutfilm-shared/permissions"
	"github.com/VidroX/cutcutfilm-shared/utils"
	"github.com/VidroX/cutcutfilm/services/identity/core/database/models"
	"github.com/VidroX/cutcutfilm/services/identity/core/environment"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type NebulaDb struct {
	*gorm.DB
}

func (db *NebulaDb) AutoMigrateAll() {
	err := db.AutoMigrate(
		&models.Permission{},
		&models.UserPermission{},
	)

	if err != nil {
		log.Fatalf("Unable to migrate database models: %s", err.Error())
	}
}

func (db *NebulaDb) PopulatePermissions() {
	isAddedAny := false

	for _, permission := range permissions.AllPermissions {
		dbPermission := models.Permission{}
		db.First(&dbPermission, "action = ?", permission.Action)

		if len(dbPermission.Action) > 0 {
			continue
		}

		dbPermission.Action = permission.Action
		dbPermission.Description = permission.Description

		err := db.Create(&dbPermission).Error

		if err != nil {
			log.Fatalf("Unable to populate permission. Error: %v", err)
			return
		}

		isAddedAny = true
	}

	if isAddedAny {
		log.Println("Successfully populated permissions!")
	}
}

func (db *NebulaDb) SetAdminPermissions() {
	adminId := os.Getenv(environment.KeysAdminID)
	if utils.UtilString(adminId).IsEmpty() {
		return
	}

	var count int64 = 0
	db.Model(&models.UserPermission{}).Count(&count)

	if count > 0 {
		return
	}

	adminPermissionRead := models.UserPermission{
		UserID: strings.TrimSpace(adminId),
		Permission: models.Permission{
			Action:      "read:admin",
			Description: "Admin read access",
		},
	}

	adminPermissionWrite := models.UserPermission{
		UserID: strings.TrimSpace(adminId),
		Permission: models.Permission{
			Action:      "write:admin",
			Description: "Admin write access",
		},
	}

	err := db.Create(&adminPermissionRead).Error
	err2 := db.Create(&adminPermissionWrite).Error

	if err != nil || err2 != nil {
		log.Fatalf("Unable to create default admin user permissions. Error: %v", err)
		return
	}

	log.Println("Successfully created default admin user permissions!")
}

func Init() *NebulaDb {
	gormConfig := &gorm.Config{}

	if !strings.EqualFold(os.Getenv(environment.KeysDebug), "True") {
		gormConfig.Logger = logger.Default.LogMode(logger.Silent)
	}

	gormDB, err := gorm.Open(postgres.Open(
		fmt.Sprintf(
			"host=%s user=%s password=%s dbname=%s port=%s sslmode=prefer TimeZone=America/Vancouver",
			os.Getenv(environment.KeysDatabaseHost),
			os.Getenv(environment.KeysDatabaseUsername),
			os.Getenv(environment.KeysDatabasePassword),
			os.Getenv(environment.KeysDatabaseName),
			os.Getenv(environment.KeysDatabasePort),
		),
	), gormConfig)

	if err != nil {
		log.Fatalf("Unable to connect to the Database: %v", err)
	}

	log.Println("Successfully connected to the Database!")

	return &NebulaDb{gormDB}
}
