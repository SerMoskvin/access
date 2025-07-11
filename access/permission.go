package access

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v4"
)

type contextKey string

const (
	userClaimsKey contextKey = "GOMusic_contextKey"
)

// Извлечение JWT из заголовка Authorization
func extractToken(r *http.Request) string {
	bearerToken := r.Header.Get("Authorization")
	if bearerToken == "" {
		return ""
	}
	parts := strings.Split(bearerToken, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ""
	}
	return parts[1]
}

func (a *Authenticator) CheckPermissions(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := extractToken(r)
		if tokenString == "" {
			http.Error(w, "Требуется авторизация", http.StatusUnauthorized)
			return
		}

		claims, err := a.ParseJWT(tokenString)
		if err != nil {
			http.Error(w, "Неверный токен", http.StatusUnauthorized)
			return
		}

		role, ok := claims["role"].(string)
		if !ok {
			http.Error(w, "Некорректная роль в токене", http.StatusForbidden)
			return
		}

		perms, ok := PermissionsMap[role]
		if !ok {
			http.Error(w, "Доступ запрещён: роль не найдена", http.StatusForbidden)
			return
		}

		path := r.URL.Path
		method := r.Method

		var hasAccess bool
		for _, section := range perms.Sections {
			if strings.HasPrefix(path, section.URL) {
				if method == http.MethodGet && section.CanRead {
					hasAccess = true
					break
				}
				if (method == http.MethodPost || method == http.MethodPut || method == http.MethodDelete) && section.CanWrite {
					hasAccess = true
					break
				}
			}
		}

		if !hasAccess {
			http.Error(w, "Доступ запрещён", http.StatusForbidden)
			return
		}
		ctx := context.WithValue(r.Context(), userClaimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Проверка доступа только к записям по своему ID
func (a *Authenticator) CheckOwnRecords(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(userClaimsKey).(jwt.MapClaims)
		if !ok {
			http.Error(w, "User claims not found", http.StatusInternalServerError)
			return
		}

		role, ok := claims["role"].(string)
		if !ok {
			http.Error(w, "Invalid role in token", http.StatusForbidden)
			return
		}

		userID, ok := claims["user_id"].(float64)
		if !ok {
			http.Error(w, "Invalid user ID in token", http.StatusForbidden)
			return
		}

		perms, ok := PermissionsMap[role]
		if !ok {
			http.Error(w, "Access denied: unknown role", http.StatusForbidden)
			return
		}

		if perms.OwnRecordsOnly {
			requestedID := chi.URLParam(r, "id")
			if requestedID != fmt.Sprintf("%.0f", userID) {
				http.Error(w, "You can only access your own records", http.StatusForbidden)
				return
			}

			if method := r.Method; method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
				bodyBytes, err := io.ReadAll(r.Body)
				if err != nil {
					http.Error(w, "Failed to read request body", http.StatusBadRequest)
					return
				}

				// Восстанавливаем тело для дальнейшего использования
				r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

				var body map[string]interface{}
				if err := json.NewDecoder(bytes.NewReader(bodyBytes)).Decode(&body); err == nil {
					if bodyID, ok := body["user_id"].(float64); ok && int(bodyID) != int(userID) {
						http.Error(w, "Cannot modify other users' data", http.StatusForbidden)
						return
					}
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}
