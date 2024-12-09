package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// Algorithm used for signing tokens
	signingMethod = jwt.SigningMethodHS256
)

// TokenManager provides an interface for generating and verifying RFC 7519 JWT tokens for authentication.
type TokenManager struct {
	accessSecretKey  string
	refreshSecretKey string
	accessTTL        time.Duration
	refreshTTL       time.Duration
}

// NewTokenManager creates a new TokenManager with the provided secret keys and token TTLs.
func NewTokenManager(accessSecretKey, refreshSecretKey string, accessTTL, refreshTTL time.Duration) *TokenManager {
	return &TokenManager{
		accessSecretKey:  accessSecretKey,
		refreshSecretKey: refreshSecretKey,
		accessTTL:        accessTTL,
		refreshTTL:       refreshTTL,
	}
}

// GenerateAccessToken generates a new access token for a user ID using RFC 7519 claims.
func (tm *TokenManager) GenerateAccessToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(tm.accessTTL).Unix(),
	}
	token := jwt.NewWithClaims(signingMethod, claims)
	return token.SignedString([]byte(tm.accessSecretKey))
}

// GenerateRefreshToken generates a new refresh token for a user ID using RFC 7519 claims.
func (tm *TokenManager) GenerateRefreshToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(tm.refreshTTL).Unix(),
	}
	token := jwt.NewWithClaims(signingMethod, claims)
	return token.SignedString([]byte(tm.refreshSecretKey))
}

func (tm *TokenManager) VerifyAccessToken(tokenString string) (jwt.MapClaims, error) {
	return parseToken(tokenString, tm.accessSecretKey)
}

func (tm *TokenManager) VerifyRefreshToken(tokenString string) (jwt.MapClaims, error) {
	return parseToken(tokenString, tm.refreshSecretKey)
}

func parseToken(tokenString string, secretKey string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, jwt.ErrSignatureInvalid
	}
	return claims, nil
}
