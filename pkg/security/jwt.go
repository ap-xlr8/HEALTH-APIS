package security

import (
	"crypto/rsa"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Claims struct {
	UserID string `json:"uid"`
	Role   string `json:"role"`
	Kind   string `json:"kind"`
	jwt.RegisteredClaims
}

func ParseRSAPrivateKey(pem string) (*rsa.PrivateKey, error) {
	return jwt.ParseRSAPrivateKeyFromPEM([]byte(pem))
}

func ParseRSAPublicKey(pem string) (*rsa.PublicKey, error) {
	return jwt.ParseRSAPublicKeyFromPEM([]byte(pem))
}

func SignJWT(privateKey *rsa.PrivateKey, userID, role, kind string, ttl time.Duration) (string, string, error) {
	now := time.Now().UTC()
	jti := kind + "_" + uuid.NewString()
	claims := Claims{
		UserID: userID,
		Role:   role,
		Kind:   kind,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    "healthos",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        jti,
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(privateKey)
	return token, jti, err
}

func VerifyJWT(publicKey *rsa.PublicKey, tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, errors.New("unexpected signing algorithm")
		}
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}
