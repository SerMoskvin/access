package access

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v4"
)

type contextKey string

const (
	userClaimsKey contextKey = "GOMusic_contextKey"
)

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
		a.configMu.RLock()
		cfg := a.permissionsConfig
		a.configMu.RUnlock()

		if cfg == nil {
			if err := a.LoadPermissions(a.cfg.Permissions.Path); err != nil {
				http.Error(w, "Failed to load permissions configuration", http.StatusInternalServerError)
				return
			}
			a.configMu.RLock()
			cfg = a.permissionsConfig
			a.configMu.RUnlock()
		}

		tokenString := extractToken(r)
		if tokenString == "" {
			http.Error(w, "Authorization required", http.StatusUnauthorized)
			return
		}

		// Кэширование токена
		var claims jwt.MapClaims
		if cachedClaims, ok := a.TokenCache.Get(tokenString); ok {
			claims = cachedClaims.(jwt.MapClaims)
		} else {
			var err error
			claims, err = a.JwtService.ParseJWT(tokenString)
			if err != nil {
				http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
				return
			}
			a.TokenCache.Set(tokenString, claims)
		}

		role, ok := claims["role"].(string)
		if !ok {
			http.Error(w, "Invalid role in token", http.StatusForbidden)
			return
		}

		path := r.URL.Path
		method := r.Method

		// Кэширование прав доступа
		cacheKey := role + ":" + path + ":" + method
		if cachedAccess, ok := a.permissionCache.Get(cacheKey); ok {
			if !cachedAccess.(bool) {
				http.Error(w, "Access denied", http.StatusForbidden)
				return
			}
			ctx := context.WithValue(r.Context(), userClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		perms, ok := cfg.Roles[role]
		if !ok {
			http.Error(w, "Access denied: role not found", http.StatusForbidden)
			return
		}

		var hasAccess bool
		for _, section := range perms.Sections {
			if strings.HasPrefix(path, section.URL) {
				switch method {
				case http.MethodGet, http.MethodHead, http.MethodOptions:
					if section.CanRead {
						hasAccess = true
						break
					}
				case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
					if section.CanWrite {
						hasAccess = true
						break
					}
				}
			}
			if hasAccess {
				break
			}
		}

		a.permissionCache.Set(cacheKey, hasAccess)

		if !hasAccess {
			http.Error(w, "Access denied", http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), userClaimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *Authenticator) CheckOwnRecords(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(userClaimsKey).(jwt.MapClaims)
		if !ok {
			http.Error(w, "Authentication required", http.StatusUnauthorized)
			return
		}

		role, ok := claims["role"].(string)
		userID, okID := claims["user_id"].(float64)
		if !ok || !okID {
			http.Error(w, "Invalid user credentials", http.StatusForbidden)
			return
		}
		intUserID := int(userID)

		a.configMu.RLock()
		permsConfig := a.permissionsConfig
		a.configMu.RUnlock()

		if permsConfig == nil {
			if err := a.LoadPermissions(a.cfg.Permissions.Path); err != nil {
				http.Error(w, "Configuration error", http.StatusInternalServerError)
				return
			}
			a.configMu.RLock()
			permsConfig = a.permissionsConfig
			a.configMu.RUnlock()
		}

		perms, ok := permsConfig.Roles[role]
		if !ok || !perms.OwnRecordsOnly {
			next.ServeHTTP(w, r)
			return
		}

		if requestedID := chi.URLParam(r, "id"); requestedID != "" && requestedID != strconv.Itoa(intUserID) {
			http.Error(w, "Access to this resource is denied", http.StatusForbidden)
			return
		}

		if isModifyingMethod(r.Method) {
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Invalid request", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			if bytes.Contains(bodyBytes, []byte(`"user_id"`)) {
				var body struct {
					UserID int `json:"user_id"`
				}
				if err := json.Unmarshal(bodyBytes, &body); err == nil && body.UserID != 0 && body.UserID != intUserID {
					http.Error(w, "Data ownership violation", http.StatusForbidden)
					return
				}
			}
		}

		ctx := context.WithValue(r.Context(), contextKey("user_id"), intUserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func isModifyingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}
