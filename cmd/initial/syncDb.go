package initial

import "auth_serv/cmd/models"

func SyncDatabase() {
	DB.AutoMigrate(&models.User{})
}
