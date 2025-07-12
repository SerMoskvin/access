package access_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SerMoskvin/access"
	"github.com/go-chi/chi/v5"
)

func TestCheckPermissions(t *testing.T) {
	auth := access.NewAuthenticator("test-secret")

	// Создаем тестовый сервер
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
			name:       "Admin read access",
			role:       "admin",
			path:       "/users",
			method:     http.MethodGet,
			wantStatus: http.StatusOK,
		},
		{
			name:       "Student write denied",
			role:       "student",
			path:       "/grades",
			method:     http.MethodPost,
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, _ := auth.GenerateJWT(1, "test", tt.role, 1*time.Hour)

			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.Header.Set("Authorization", "Bearer "+token)

			rr := httptest.NewRecorder()
			auth.CheckPermissions(handler).ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("Expected status %d, got %d", tt.wantStatus, rr.Code)
			}
		})
	}

	t.Run("No token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rr := httptest.NewRecorder()
		auth.CheckPermissions(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, rr.Code)
		}
	})
}

func TestCheckOwnRecords(t *testing.T) {
	auth := access.NewAuthenticator("test-secret")

	// Сохраняем оригинальные права доступа
	originalPermissions := make(map[string]access.RolePermissions)
	for k, v := range access.PermissionsMap {
		originalPermissions[k] = v
	}

	// Восстанавливаем оригинальные права после тестов
	defer func() {
		access.PermissionsMap = originalPermissions
	}()

	// Создаем тестовый роутер chi
	createTestRouter := func(auth *access.Authenticator) *chi.Mux {
		r := chi.NewRouter()

		// Тестовый обработчик успешного запроса
		successHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		// Настраиваем маршруты с middleware
		r.Route("/grades", func(r chi.Router) {
			r.With(auth.CheckPermissions, auth.CheckOwnRecords).Get("/{id}", successHandler)
			r.With(auth.CheckPermissions, auth.CheckOwnRecords).Post("/", successHandler)
		})

		r.Route("/students", func(r chi.Router) {
			r.With(auth.CheckPermissions, auth.CheckOwnRecords).Get("/{id}", successHandler)
		})

		return r
	}

	t.Run("Allow access to own record via URL (student role)", func(t *testing.T) {
		router := createTestRouter(auth)
		userID := 42
		token, _ := auth.GenerateJWT(userID, "student", "student", 1*time.Hour)

		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/grades/%d", userID), nil)
		req.Header.Set("Authorization", "Bearer "+token)

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d (body: %s)", http.StatusOK, rr.Code, rr.Body.String())
		}
	})

	t.Run("Deny access to others records via URL (student role)", func(t *testing.T) {
		router := createTestRouter(auth)
		userID := 1
		token, _ := auth.GenerateJWT(userID, "student", "student", 1*time.Hour)

		req := httptest.NewRequest(http.MethodGet, "/grades/42", nil) // Чужой ID
		req.Header.Set("Authorization", "Bearer "+token)

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("Expected status %d, got %d (body: %s)", http.StatusForbidden, rr.Code, rr.Body.String())
		}
	})

	t.Run("Allow modifying own record via URL (teacher role)", func(t *testing.T) {
		// 1. Инициализация тестового роутера
		router := chi.NewRouter()

		// 2. Настройка маршрута с middleware
		router.With(
			auth.CheckPermissions,
			auth.CheckOwnRecords,
		).Put("/grades/{id}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK) // Успешный обработчик
		}))

		// 3. Подготовка тестовых данных
		teacherID := 10
		token, _ := auth.GenerateJWT(teacherID, "teacher", "teacher", time.Hour)

		// 4. Формирование тела запроса
		requestBody := map[string]interface{}{
			"grade":    "A+",
			"comments": "Отличная работа",
		}
		bodyBytes, _ := json.Marshal(requestBody)

		// 5. Создание тестового запроса
		req := httptest.NewRequest(
			http.MethodPut,
			fmt.Sprintf("/grades/%d", teacherID), // Собственный ID
			bytes.NewReader(bodyBytes),
		)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		// 6. Выполнение запроса
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		// 7. Проверка результата
		if rr.Code != http.StatusOK {
			t.Errorf(
				"Expected status %d, got %d. Response body: %s",
				http.StatusOK,
				rr.Code,
				rr.Body.String(),
			)
		}
	})

	t.Run("Deny modifying others records via body (teacher role)", func(t *testing.T) {
		router := createTestRouter(auth)
		userID := 10
		token, _ := auth.GenerateJWT(userID, "teacher", "teacher", 1*time.Hour)

		body := map[string]interface{}{"user_id": 20} // Чужой ID
		bodyBytes, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/grades", bytes.NewReader(bodyBytes))
		req.Header.Set("Authorization", "Bearer "+token)

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("Expected status %d, got %d (body: %s)", http.StatusForbidden, rr.Code, rr.Body.String())
		}
	})

	t.Run("Admin can access any record", func(t *testing.T) {
		router := createTestRouter(auth)
		userID := 1
		token, _ := auth.GenerateJWT(userID, "admin", "admin", 1*time.Hour)

		req := httptest.NewRequest(http.MethodGet, "/students/42", nil) // Чужой ID
		req.Header.Set("Authorization", "Bearer "+token)

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d (body: %s)", http.StatusOK, rr.Code, rr.Body.String())
		}
	})
}
