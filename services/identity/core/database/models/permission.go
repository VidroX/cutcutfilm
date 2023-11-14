package models

type Permission struct {
	Name        string `json:"name" gorm:"primaryKey;type:varchar(255)"`
	Description string `json:"description" gorm:"type:text"`
}
