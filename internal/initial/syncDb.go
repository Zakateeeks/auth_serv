package initial

import (
	"auth_serv/internal/models"
)

func SyncDatabase() {
	DB.AutoMigrate(&models.User{})
}
