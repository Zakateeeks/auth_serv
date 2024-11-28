package controllers

import (
	"auth_serv/cmd/initial"
	"auth_serv/cmd/models"
	"crypto/rand"
	"encoding/base64"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"os"
	"time"
)

func generateRefreshToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b), nil
}

func SignUp(c *gin.Context) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 12)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to generate hash password",
		})
	}
	user := models.User{Email: body.Email, Password: string(hash)}
	result := initial.DB.Create(&user)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create user",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{})
}

func GetData(c *gin.Context) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to read body",
		})
		return
	}

	var user models.User
	initial.DB.First(&user, "email = ?", body.Email)

	if user.ID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid email or password",
		})
		return
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid email or password",
		})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 1).Unix(),
		"ip":  c.ClientIP(),
	})

	tokenString, err := token.SignedString([]byte(os.Getenv("TOKEN")))

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Failed to create access token",
		})
		return
	}

	var refreshToken string
	if user.RefreshToken == "" {
		refreshToken, err := generateRefreshToken()
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Failed to create refresh token",
			})
			return
		}
		hashRefresh, err := bcrypt.GenerateFromPassword([]byte(refreshToken), 12)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Failed to create refresh token",
			})
			return
		}
		user.RefreshToken = string(hashRefresh)
		initial.DB.Save(&user)
	} else {
		refreshToken = user.RefreshToken
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  tokenString,
		"refresh_token": refreshToken,
	})

}

func Refresh(c *gin.Context) {

}
