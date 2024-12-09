package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestNewTokenManager(t *testing.T) {
	accessSecret := "access-secret"
	refreshSecret := "refresh-secret"
	accessTTL := time.Minute * 15
	refreshTTL := time.Hour * 24

	tm := NewTokenManager(accessSecret, refreshSecret, accessTTL, refreshTTL)

	t.Run("Generate and Verify Access Token", func(t *testing.T) {
		userID := "user-id"
		token, err := tm.GenerateAccessToken(userID)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		claims, err := tm.VerifyAccessToken(token)
		assert.NoError(t, err)
		assert.Equal(t, userID, claims["sub"])
	})

	t.Run("Generate and Verify Refresh Token", func(t *testing.T) {
		userID := "user-id"
		token, err := tm.GenerateRefreshToken(userID)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		claims, err := tm.VerifyRefreshToken(token)
		assert.NoError(t, err)
		assert.Equal(t, userID, claims["sub"])
	})
	t.Run("Verify Access Token - Invalid Signature", func(t *testing.T) {
		userID := "user123"

		// Generate Access Token with valid manager
		accessToken, err := tm.GenerateAccessToken(userID)
		assert.NoError(t, err)

		// Verify with a different secret key
		invalidTM := NewTokenManager("wrong-secret", refreshSecret, accessTTL, refreshTTL)
		_, err = invalidTM.VerifyAccessToken(accessToken)
		assert.Error(t, err)
		assert.ErrorIs(t, err, jwt.ErrSignatureInvalid)
	})

	t.Run("Verify Expired Access Token", func(t *testing.T) {
		expiredTM := NewTokenManager(accessSecret, refreshSecret, time.Second, refreshTTL)
		userID := "user123"

		// Generate a token with very short TTL
		accessToken, err := expiredTM.GenerateAccessToken(userID)
		assert.NoError(t, err)

		// Wait for the token to expire
		time.Sleep(2 * time.Second)

		// Verify expired token
		_, err = tm.VerifyAccessToken(accessToken)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token is expired")
	})

	t.Run("Verify Malformed Token", func(t *testing.T) {
		malformedToken := "this.is.not.a.valid.jwt"

		// Verify malformed token
		_, err := tm.VerifyAccessToken(malformedToken)
		assert.Error(t, err)
		assert.NotNil(t, err)
	})

}
