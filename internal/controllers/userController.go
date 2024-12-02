package controllers

import (
	"auth_serv/internal/initial"
	"auth_serv/internal/models"
	"auth_serv/internal/utils"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"os"
)

// SignUp Функкция, реализующая запрос /signup
// Создаёт refresh и access токен пользователю, в случае если он не создан
// если пользователь существует, то выводит токены пользователю
func SignUp(c *gin.Context) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read body"})
		return
	}
	/*
		Этот участок кода отвечает за вывод refresh и access токенов
		в случае, если пользователь уже зарегистрирован.
	*/
	var existUser models.User
	initial.DB.Where("email = ?", body.Email).First(&existUser)
	if existUser.Email != "" {
		cookieToken, err := c.Cookie("access_token")
		if err == nil {
			token, err := jwt.Parse(cookieToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("Unexpected signing method")
				}
				return []byte(os.Getenv("TOKEN")), nil
			})
			if err == nil && token.Valid {
				c.JSON(http.StatusOK, gin.H{
					"access_token":  cookieToken,
					"refresh_token": existUser.RefreshToken,
				})
				return
			}
		}
		tokenString, err := utils.CreateJWTToken(existUser.ID, c.ClientIP())
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create token"})
			return
		}
		refreshToken, err := utils.GenerateRefreshToken()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to generate refresh token"})
			return
		}
		hashRefresh, err := utils.HashRefreshToken(refreshToken)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to hash refresh token"})
			return
		}

		existUser.RefreshToken = hashRefresh
		initial.DB.Save(&existUser)
		c.SetCookie("access_token", tokenString, 3600, "/", "", false, true)

		c.JSON(http.StatusOK, gin.H{
			"access_token":  tokenString,
			"refresh_token": refreshToken,
		})
		return
	}

	/*
		Этот участок кода отвечает за регистрацию пользователя,
		добавление данных в БД и генерацию access и refresh токенов.
	*/
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 12)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to generate hash password"})
		return
	}

	user := models.User{Email: body.Email, Password: string(hash)}
	result := initial.DB.Create(&user)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create user"})
		return
	}

	tokenString, err := utils.CreateJWTToken(user.ID, c.ClientIP())

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create access token"})
	}

	refreshToken, err := utils.GenerateRefreshToken()
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to create refresh token"})
		return
	}

	hashRefresh, err := utils.HashRefreshToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to create hash refresh token"})
		return
	}

	user.RefreshToken = hashRefresh
	initial.DB.Save(&user)

	c.SetCookie("access_token", tokenString, 3600, "/", "", false, true)

	c.JSON(http.StatusOK, gin.H{
		"access_token":  tokenString,
		"refresh_token": refreshToken,
	})
}

// Refresh Функция, реализуцющая запрос refresh
// Обновляет refresh и access токен пользователя
func Refresh(c *gin.Context) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read body"})
		return
	}

	AccessTokenCookie, err := c.Cookie("access_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to get access token"})
		return
	}

	token, err := jwt.Parse(AccessTokenCookie, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Error 09")
		}
		return []byte(os.Getenv("TOKEN")), nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired access token"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to extract claims from token"})
		return
	}

	userID, ok := claims["sub"]
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "userID not found in token"})
		return
	}

	tokenIp, ok := claims["ip"]
	if tokenIp != c.ClientIP() {
		c.JSON(http.StatusUnauthorized, gin.H{"warning": "IP in Token different from current ip"})
	}
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "IP not found in token"})
		return
	}

	var user models.User
	initial.DB.Where("id = ?", userID).First(&user)
	if user.ID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.RefreshToken), []byte(body.RefreshToken))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	tokenString, err := utils.CreateJWTToken(user.ID, c.ClientIP())
	c.SetCookie("access_token", tokenString, 3600, "/", "", false, true)
	refreshToken, err := utils.GenerateRefreshToken()
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to create refresh token"})
		return
	}

	hashRefresh, err := utils.HashRefreshToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Failed to create hash refresh token"})
		return
	}
	user.RefreshToken = hashRefresh
	initial.DB.Save(&user)

	c.JSON(200, gin.H{
		"access_token":  tokenString,
		"refresh_token": refreshToken,
	})
}
