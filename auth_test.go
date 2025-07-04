package access

import (
	"testing"
	"time"
)

func TestHashAndCheckPassword(t *testing.T) {
	auth := NewAuthenticator("testsecret")

	password := "myStrongP@ssw0rd"
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword error: %v", err)
	}

	if !auth.CheckPasswordHash(password, hash) {
		t.Errorf("CheckPasswordHash failed for correct password")
	}

	if auth.CheckPasswordHash("wrongpassword", hash) {
		t.Errorf("CheckPasswordHash succeeded for wrong password")
	}
}

func TestGenerateAndParseJWT(t *testing.T) {
	auth := NewAuthenticator("testsecret")

	userID := 42
	username := "user42"
	role := "admin"

	tokenString, err := auth.GenerateJWT(userID, username, role)
	if err != nil {
		t.Fatalf("GenerateJWT error: %v", err)
	}

	claims, err := auth.ParseJWT(tokenString)
	if err != nil {
		t.Fatalf("ParseJWT error: %v", err)
	}

	if int64(claims["user_id"].(float64)) != int64(userID) {
		t.Errorf("Expected user_id %d, got %v", userID, claims["user_id"])
	}
	if claims["username"] != username {
		t.Errorf("Expected username %s, got %v", username, claims["username"])
	}
	if claims["role"] != role {
		t.Errorf("Expected role %s, got %v", role, claims["role"])
	}

	expUnix := int64(claims["exp"].(float64))
	if time.Unix(expUnix, 0).Before(time.Now()) {
		t.Errorf("Token expiration is in the past")
	}
}
