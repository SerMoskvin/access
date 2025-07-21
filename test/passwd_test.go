package access_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SerMoskvin/access"
	"github.com/stretchr/testify/assert"
)

func TestAuthenticator_AdminAccess(t *testing.T) {
	auth, err := access.NewAuthenticator("./test_config.yml")
	assert.NoError(t, err)

	tests := []struct {
		name     string
		role     string
		path     string
		method   string
		wantPass bool
	}{
		{
			name:     "Admin access to users",
			role:     "admin",
			path:     "/api/admin/users",
			method:   http.MethodGet,
			wantPass: true,
		},
		{
			name:     "User forbidden in admin area",
			role:     "user",
			path:     "/api/admin/users",
			method:   http.MethodGet,
			wantPass: false,
		},
		{
			name:     "Moderator content access",
			role:     "moderator",
			path:     "/api/mod/posts",
			method:   http.MethodDelete,
			wantPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := auth.JwtService.GenerateJWT(1, "test", tt.role)
			assert.NoError(t, err)

			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.Header.Set("Authorization", "Bearer "+token)

			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			auth.CheckPermissions(handler).ServeHTTP(rr, req)

			if tt.wantPass {
				assert.Equal(t, http.StatusOK, rr.Code)
			} else {
				assert.Equal(t, http.StatusForbidden, rr.Code)
			}
		})
	}
}

func TestPasswordHashing_CostVariations(t *testing.T) {
	auth, err := access.NewAuthenticator("./test_config.yml")
	assert.NoError(t, err)

	tests := []struct {
		cost     int
		password string
	}{
		{cost: 6, password: "test123"},
		{cost: 8, password: "admin!@#"},
		{cost: 10, password: "super-secure"},
	}

	for _, tt := range tests {
		t.Run(tt.password, func(t *testing.T) {
			ph := access.NewPasswordHasher(tt.cost, auth)
			hash, err := ph.HashPassword(tt.password)
			assert.NoError(t, err)
			assert.True(t, ph.CheckPasswordHash(tt.password, hash))
		})
	}
}

func TestJWT_Rotation(t *testing.T) {
	auth, err := access.NewAuthenticator("./test_config.yml")
	assert.NoError(t, err)

	svc := auth.JwtService

	// 1. Первый токен
	token1, _ := svc.GenerateJWT(1, "user1", "user")

	// 2. Первая ротация (должна сохранить исходный ключ)
	svc.RotateSecret("new-secret-1")
	token2, _ := svc.GenerateJWT(2, "user2", "admin")

	// Очищаем кеш перед проверкой
	auth.TokenCache.Clear()

	// Оба токена должны работать
	_, err = svc.ParseJWT(token1)
	assert.NoError(t, err)

	_, err = svc.ParseJWT(token2)
	assert.NoError(t, err)

	// 3. Вторая ротация (должна удалить исходный ключ)
	svc.RotateSecret("new-secret-2")
	auth.TokenCache.Clear() // Очищаем кеш

	// token1 НЕ должен проходить проверку
	_, err = svc.ParseJWT(token1)
	if err == nil {
		t.Fatal("Token1 should be invalid after second rotation")
	}

	// token2 должен работать
	_, err = svc.ParseJWT(token2)
	assert.NoError(t, err)

	// 4. Третья ротация (должна удалить new-secret-1)
	svc.RotateSecret("new-secret-3")
	auth.TokenCache.Clear() // Очищаем кеш

	// token2 НЕ должен проходить проверку
	_, err = svc.ParseJWT(token2)
	if err == nil {
		t.Fatal("Token2 should be invalid after third rotation")
	}

	// token1 тем более не должен работать
	_, err = svc.ParseJWT(token1)
	if err == nil {
		t.Fatal("Token1 should still be invalid")
	}

	// Новый токен должен работать
	token3, _ := svc.GenerateJWT(3, "user3", "admin")
	_, err = svc.ParseJWT(token3)
	assert.NoError(t, err)
}
