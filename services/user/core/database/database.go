package database

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/VidroX/cutcutfilm-shared/utils"
	"github.com/VidroX/cutcutfilm/services/user/core/environment"
	"github.com/VidroX/cutcutfilm/services/user/graph/model"
	"github.com/alexedwards/argon2id"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type NebulaDb struct {
	*gorm.DB
}

func (db *NebulaDb) AutoMigrateAll() {
	err := db.AutoMigrate(
		&model.User{},
	)

	if err != nil {
		log.Fatalf("Unable to migrate database models: %s", err.Error())
	}
}

func (db *NebulaDb) CreateAdminUser() {
	userId := os.Getenv(environment.KeysAdminID)
	email := os.Getenv(environment.KeysAdminEmail)
	userName := os.Getenv(environment.KeysAdminUsername)
	password := os.Getenv(environment.KeysAdminPassword)

	if utils.UtilString(email).IsEmpty() ||
		utils.UtilString(password).IsEmpty() ||
		utils.UtilString(userName).IsEmpty() ||
		utils.UtilString(userId).IsEmpty() {
		return
	}

	var count int64 = 0
	db.Model(&model.User{}).Count(&count)

	if count > 0 {
		return
	}

	hashedPassword, _ := argon2id.CreateHash(password, argon2id.DefaultParams)

	adminUser := model.User{
		ID:       strings.TrimSpace(userId),
		EMail:    strings.TrimSpace(email),
		Username: strings.TrimSpace(userName),
		Password: hashedPassword,
	}

	err := db.Create(&adminUser).Error

	if err != nil {
		log.Fatalf("Unable to create default admin user. Error: %v", err)
		return
	}

	log.Println("Successfully created default admin user!")
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
