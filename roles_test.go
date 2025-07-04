package access

import (
	"testing"
)

func TestParseJWTWithUnknownRoles(t *testing.T) {
	auth := NewAuthenticator("testsecret")

	roles := []string{"student", "teacher", "admin", "guest", "custom_role_123"}

	for _, role := range roles {
		tokenString, err := auth.GenerateJWT(1, "user", role)
		if err != nil {
			t.Fatalf("GenerateJWT error for role %s: %v", role, err)
		}

		claims, err := auth.ParseJWT(tokenString)
		if err != nil {
			t.Fatalf("ParseJWT error for role %s: %v", role, err)
		}

		gotRole, ok := claims["role"].(string)
		if !ok {
			t.Errorf("Role claim is not string for role %s", role)
		}
		if gotRole != role {
			t.Errorf("Expected role %s, got %s", role, gotRole)
		}
	}
}
