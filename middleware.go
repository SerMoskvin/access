package access

import (
	"context"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
)

// AuthOnly - только проверка аутентификации без проверки прав
func (a *Authenticator) AuthOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := extractToken(r)
		if tokenString == "" {
			http.Error(w, "Authorization required", http.StatusUnauthorized)
			return
		}

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

		ctx := context.WithValue(r.Context(), UserClaimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// OptionalAuth - необязательная аутентификация (для публичных эндпоинтов)
func (a *Authenticator) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := extractToken(r)
		if tokenString != "" {
			if claims, err := a.JwtService.ParseJWT(tokenString); err == nil {
				ctx := context.WithValue(r.Context(), UserClaimsKey, claims)
				r = r.WithContext(ctx)
			}
		}
		next.ServeHTTP(w, r)
	})
}
