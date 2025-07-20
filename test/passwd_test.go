package access_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
			ph := access.NewPasswordHasher(tt.cost)
			hash, err := ph.HashPassword(tt.password)
			assert.NoError(t, err)
			assert.True(t, ph.CheckPasswordHash(tt.password, hash))
		})
	}
}

func TestJWT_Rotation(t *testing.T) {
	cfg := &access.Config{
		JWT: struct {
			Secret         string        `yaml:"secret"`
			RotationPeriod time.Duration `yaml:"rotation_period"`
			TTL            time.Duration `yaml:"ttl"`
			OldKeysToKeep  int           `yaml:"old_keys_to_keep"`
		}{
			Secret:        "rotate-test",
			TTL:           time.Hour,
			OldKeysToKeep: 1,
		},
	}

	svc := access.NewJWTService(cfg.JWT.Secret, cfg)
	token1, _ := svc.GenerateJWT(1, "user1", "user")

	svc.RotateSecret("new-secret-1")
	token2, _ := svc.GenerateJWT(2, "user2", "admin")

	_, err1 := svc.ParseJWT(token1)
	_, err2 := svc.ParseJWT(token2)
	assert.NoError(t, err1)
	assert.NoError(t, err2)

	svc.RotateSecret("new-secret-2")
	_, err := svc.ParseJWT(token1)
	assert.Error(t, err)
}
