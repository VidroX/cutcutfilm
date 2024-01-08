package models

type RevokedToken struct {
	Token string `json:"token" gorm:"type:text;primaryKey"`
}
