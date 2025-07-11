package access

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v4"
)

// extractToken достаёт JWT из заголовка Authorization
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
		//Достаём токен из заголовка
		tokenString := extractToken(r)
		if tokenString == "" {
			http.Error(w, "Требуется авторизация", http.StatusUnauthorized)
			return
		}

		//Парсим токен
		claims, err := a.ParseJWT(tokenString)
		if err != nil {
			http.Error(w, "Неверный токен", http.StatusUnauthorized)
			return
		}

		//Проверяем роль
		role, ok := claims["role"].(string)
		if !ok {
			http.Error(w, "Некорректная роль в токене", http.StatusForbidden)
			return
		}

		// 4. Проверяем доступ для роли
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
		ctx := context.WithValue(r.Context(), "userClaims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
		next.ServeHTTP(w, r)
	})
}

// CheckOwnRecords проверяет, может ли пользователь доступ только к своим записям
func (a *Authenticator) CheckOwnRecords(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//Получаем claims из контекста
		claims, ok := r.Context().Value("userClaims").(jwt.MapClaims)
		if !ok {
			http.Error(w, "User claims not found", http.StatusInternalServerError)
			return
		}

		//Извлекаем роль и ID пользователя
		role, ok := claims["role"].(string)
		if !ok {
			http.Error(w, "Invalid role in token", http.StatusForbidden)
			return
		}

		userID, ok := claims["user_id"].(float64) // JWT числа всегда float64
		if !ok {
			http.Error(w, "Invalid user ID in token", http.StatusForbidden)
			return
		}

		//Проверяем, требует ли роль доступ только к своим записям
		perms, ok := PermissionsMap[role]
		if !ok {
			http.Error(w, "Access denied: unknown role", http.StatusForbidden)
			return
		}

		if perms.OwnRecordsOnly {
			//Для GET /resource/{id} проверяем, что id == userID
			requestedID := chi.URLParam(r, "id")
			if requestedID != fmt.Sprintf("%.0f", userID) {
				http.Error(w, "You can only access your own records", http.StatusForbidden)
				return
			}

			// 5. Для POST/PUT/PATCH проверяем, что в теле запроса user_id == userID из токена
			if method := r.Method; method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch {
			}
		}

		next.ServeHTTP(w, r)
	})
}
