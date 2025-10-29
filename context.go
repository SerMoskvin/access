package access

import (
	"context"

	"github.com/golang-jwt/jwt/v4"
)

func GetUserIDFromContext(ctx context.Context) (int, bool) {
	userID, ok := ctx.Value(contextKey("user_id")).(int)
	return userID, ok
}

func GetUserRoleFromContext(ctx context.Context) (string, bool) {
	claims, ok := ctx.Value(UserClaimsKey).(jwt.MapClaims)
	if !ok {
		return "", false
	}
	role, ok := claims["role"].(string)
	return role, ok
}

func GetUsernameFromContext(ctx context.Context) (string, bool) {
	claims, ok := ctx.Value(UserClaimsKey).(jwt.MapClaims)
	if !ok {
		return "", false
	}
	username, ok := claims["username"].(string)
	return username, ok
}
