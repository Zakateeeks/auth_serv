package main

import (
	"auth_serv/internal/controllers"
	"auth_serv/internal/initial"
	"github.com/gin-gonic/gin"
)

// Функция для инициализации БД и переменног окружения
func init() {
	initial.LoadEnvVar()
	initial.ConnectToDb()
	initial.SyncDatabase()
}

// Инициализация HTTP сервера с 2-мя REST эндпоинтами
func main() {
	r := gin.Default()

	r.POST("/signup", controllers.SignUp)
	r.POST("/refresh", controllers.Refresh)

	r.Run()
}
