package access_test

import (
	"testing"
	"time"

	"github.com/SerMoskvin/access"
)

func TestAuthenticator(t *testing.T) {
	secret := "test-secret-123"
	auth := access.NewAuthenticator(secret)

	t.Run("Password Hashing", func(t *testing.T) {
		password := "secure-password-123"
		hash, err := auth.HashPassword(password)
		if err != nil {
			t.Fatalf("HashPassword failed: %v", err)
		}

		// Проверка корректного пароля
		if !auth.CheckPasswordHash(password, hash) {
			t.Error("CheckPasswordHash failed for correct password")
		}

		// Проверка неверного пароля
		if auth.CheckPasswordHash("wrong-password", hash) {
			t.Error("CheckPasswordHash passed for wrong password")
		}
	})

	t.Run("JWT Generation and Parsing", func(t *testing.T) {
		userID := 42
		username := "testuser"
		role := "admin"
		expiresIn := 1 * time.Hour

		token, err := auth.GenerateJWT(userID, username, role, expiresIn)
		if err != nil {
			t.Fatalf("GenerateJWT failed: %v", err)
		}

		claims, err := auth.ParseJWT(token)
		if err != nil {
			t.Fatalf("ParseJWT failed: %v", err)
		}

		// Проверка claims
		if claims["user_id"] != float64(userID) {
			t.Errorf("Expected user_id %d, got %v", userID, claims["user_id"])
		}

		if claims["username"] != username {
			t.Errorf("Expected username %s, got %v", username, claims["username"])
		}

		// Проверка невалидного токена
		_, err = auth.ParseJWT("invalid-token")
		if err == nil {
			t.Error("Expected error for invalid token")
		}
	})

	t.Run("Invalid JWT Cases", func(t *testing.T) {
		// Токен с неправильным методом подписи
		invalidToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
		_, err := auth.ParseJWT(invalidToken)
		if err == nil {
			t.Error("Expected error for token with invalid signing method")
		}

		// Просроченный токен
		expiredToken, _ := auth.GenerateJWT(1, "user", "role", -1*time.Hour)
		_, err = auth.ParseJWT(expiredToken)
		if err == nil {
			t.Error("Expected error for expired token")
		}
	})
}
