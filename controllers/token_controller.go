package controllers

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"

	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"

	"authentication/database"
	"authentication/models"

	helper "authentication/auth"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

var refreshTokenCollection *mongo.Collection = database.OpenCollection(database.Client, "refreshToken")

func GetTokens() gin.HandlerFunc {
	return func(c *gin.Context) {
		guid := c.Query("guid")
		if guid == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("No GUID provided")})
			c.Abort()
			return
		}

		accessToken, refreshToken := helper.GenerateTokens(guid)
		refreshToken = base64.StdEncoding.EncodeToString([]byte(refreshToken))
		c.JSON(http.StatusOK, gin.H{"access_token": accessToken, "refresh_token": refreshToken})
	}
}

func parseTokenClaims(c *gin.Context, tokenString string) (claims jwt.MapClaims, ok bool) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(os.Getenv("SECRET_KEY")), nil
	})
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if !token.Valid {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Bad tokens provided")})
		c.Abort()
		return
	}

	claims, ok = token.Claims.(jwt.MapClaims)

	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Bad tokens provided")})
		c.Abort()
		return
	}
	return
}

func RefreshTokens() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var tokens Tokens
		var revokedToken models.RevokedRefreshToken

		if c.ShouldBindJSON(&tokens) == nil {
			if tokens.AccessToken == "" || tokens.RefreshToken == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Bad tokens provided")})
				c.Abort()
				return
			}
		}

		err := godotenv.Load(".env")

		if err != nil {
			log.Fatal("Error loading .env file")
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Internal error")})
			c.Abort()
			return
		}

		data, err := base64.StdEncoding.DecodeString(tokens.RefreshToken)
		if err != nil {
			log.Println("Error while decoding refresh token")
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Bad tokens provided")})
			c.Abort()
			return
		}
		refreshToken := string(data)

		refreshClaims, success := parseTokenClaims(c, refreshToken)
		if !success {
			return
		}

		accessClaims, success := parseTokenClaims(c, tokens.AccessToken)
		if !success {
			return
		}

		if accessClaims["jti"] != refreshClaims["jti"] || accessClaims["sub"] != refreshClaims["sub"] {
			log.Println("Unmatchable tokens are given")
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Bad tokens provided")})
			c.Abort()
			return
		}

		revokedToken.ID = refreshClaims["jti"].(string)
		revokedToken.Expires_at, err = refreshClaims.GetExpirationTime()
		if err != nil {
			msg := fmt.Sprintf("Fail when getting exp time")
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}

		filter := bson.M{}
		filter["id"] = revokedToken.ID
		filter["expires_at"] = revokedToken.Expires_at
		guid := refreshClaims["sub"].(string)

		err = refreshTokenCollection.FindOne(ctx, filter).Err()
		if err != nil {
			if err == mongo.ErrNoDocuments {
				_, insertErr := refreshTokenCollection.InsertOne(ctx, revokedToken)
				if insertErr != nil {
					msg := fmt.Sprintf("Revoked token record was not created")
					c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
					return
				}
				defer cancel()

				accessToken, refreshToken := helper.GenerateTokens(guid)
				refreshToken = base64.StdEncoding.EncodeToString([]byte(refreshToken))
				c.JSON(http.StatusOK, gin.H{"access_token": accessToken, "refresh_token": refreshToken})
				return
			}
			log.Fatal(err)
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Refresh token is already used")})
		c.Abort()
	}
}
