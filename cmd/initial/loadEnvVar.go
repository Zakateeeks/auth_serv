package initial

import (
	"github.com/joho/godotenv"
	"log"
)

func LoadEnvVar() {
	err := godotenv.Load(".env")

	if err != nil {
		log.Fatal("Error loading .env file")
	}
}
