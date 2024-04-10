package auth

import (
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	uuid "github.com/satori/go.uuid"
)

func GenerateTokens(guid string) (access_string string, refresh_string string) {
	err := godotenv.Load(".env")

	if err != nil {
		log.Fatal("Error loading .env file")
	}

	mySigningKey := []byte(os.Getenv("SECRET_KEY"))
	id := uuid.NewV4().String()

	access_claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Issuer:    "test",
		Subject:   guid,
		ID:        id,
	}
	refresh_claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24 * 7)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Issuer:    "test",
		Subject:   guid,
		ID:        id,
	}

	access_token := jwt.NewWithClaims(jwt.SigningMethodHS512, access_claims)
	refresh_token := jwt.NewWithClaims(jwt.SigningMethodHS512, refresh_claims)

	access_string, err = access_token.SignedString(mySigningKey)

	if err != nil {
		log.Fatal("Error acquiring signed string for access token")
	}

	refresh_string, err = refresh_token.SignedString(mySigningKey)

	if err != nil {
		log.Fatal("Error acquiring signed string for refresh token")
	}

	return
}
