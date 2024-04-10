package models

import "github.com/golang-jwt/jwt/v5"

type RevokedRefreshToken struct {
	ID         string `bson: "_id"`
	Expires_at *jwt.NumericDate
}
