package initial

import (
	"auth_serv/internal/models"
)

// SyncDatabase Функция для автомаической миграции данных
func SyncDatabase() {
	DB.AutoMigrate(&models.User{})
}
