package main

import (
	"auth_serv/internal/controllers"
	"auth_serv/internal/initial"
	"github.com/gin-gonic/gin"
)

func init() {
	initial.LoadEnvVar()
	initial.ConnectToDb()
	initial.SyncDatabase()
}
func main() {
	r := gin.Default()

	r.POST("/signup", controllers.SignUp)
	r.POST("/refresh", controllers.Refresh)

	r.Run()
}
