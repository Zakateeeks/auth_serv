package main

import (
	"auth_serv/cmd/controllers"
	"auth_serv/cmd/initial"
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
	r.POST("/get", controllers.GetData)
	r.POST("/refresh", controllers.Refresh)

	r.Run()
}
