package models

import "gorm.io/gorm"

// User Структура пользователя в БД
type User struct {
	gorm.Model
	Email        string `gorm:"unique"`
	Password     string `gorm:"not null"`
	RefreshToken string `gorm:"not null"`
}
