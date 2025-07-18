package access_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/SerMoskvin/access"
	"github.com/go-chi/chi/v5"
)

const testConfigPath = "test_config.yml"

func getTestConfigPath(t *testing.T) string {
	t.Helper()
	absPath, err := filepath.Abs(testConfigPath)
	if err != nil {
		t.Fatalf("Failed to get absolute path: %v", err)
	}
	return absPath
}

func TestCheckPermissions(t *testing.T) {
	configPath := getTestConfigPath(t)
	auth := access.NewAuthenticator("test-secret")

	// Инициализируем конфиг
	_, err := access.GetPermissions(configPath)
	if err != nil {
		t.Fatalf("Failed to load permissions config: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	tests := []struct {
		name       string
		role       string
		path       string
		method     string
		wantStatus int
	}{
		{
			name:       "Admin can read users",
			role:       "admin",
			path:       "/users",
			method:     http.MethodGet,
			wantStatus: http.StatusOK,
		},
		{
			name:       "Admin can write students",
			role:       "admin",
			path:       "/students",
			method:     http.MethodPost,
			wantStatus: http.StatusOK,
		},
		{
			name:       "Student can read grades",
			role:       "student",
			path:       "/grades",
			method:     http.MethodGet,
			wantStatus: http.StatusOK,
		},
		{
			name:       "Student cannot write grades",
			role:       "student",
			path:       "/grades",
			method:     http.MethodPost,
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, _ := auth.GenerateJWT(1, "testuser", tt.role, time.Hour)
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.Header.Set("Authorization", "Bearer "+token)

			rr := httptest.NewRecorder()
			auth.CheckPermissions(handler).ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("%s: expected status %d, got %d", tt.name, tt.wantStatus, rr.Code)
			}
		})
	}
}

func TestCheckOwnRecords(t *testing.T) {
	configPath := getTestConfigPath(t)
	auth := access.NewAuthenticator("test-secret")

	// Инициализируем конфиг
	_, err := access.GetPermissions(configPath)
	if err != nil {
		t.Fatalf("Failed to load permissions config: %v", err)
	}

	createTestRouter := func() *chi.Mux {
		r := chi.NewRouter()
		successHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		r.Route("/grades", func(r chi.Router) {
			r.With(auth.CheckPermissions, auth.CheckOwnRecords).Get("/{id}", successHandler)
			r.With(auth.CheckPermissions, auth.CheckOwnRecords).Post("/", successHandler)
		})

		return r
	}

	t.Run("Teacher can modify own record", func(t *testing.T) {
		router := createTestRouter()
		teacherID := 10
		token, _ := auth.GenerateJWT(teacherID, "teacher1", "teacher", time.Hour)

		body := map[string]interface{}{"grade": "A"}
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(
			http.MethodPost,
			"/grades",
			bytes.NewReader(bodyBytes),
		)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
		}
	})

	t.Run("Student cannot access other's records", func(t *testing.T) {
		router := createTestRouter()
		studentID := 5
		token, _ := auth.GenerateJWT(studentID, "student1", "student", time.Hour)

		req := httptest.NewRequest(http.MethodGet, "/grades/10", nil) // Чужой ID
		req.Header.Set("Authorization", "Bearer "+token)

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("Expected status %d, got %d", http.StatusForbidden, rr.Code)
		}
	})
}
