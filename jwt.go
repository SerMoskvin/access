package access

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type JWTService struct {
	CurrentSecret []byte
	OldSecrets    [][]byte
	mu            sync.RWMutex
	cfg           *Config
	auth          *Authenticator
}

func NewJWTService(secret string, cfg *Config, auth *Authenticator) *JWTService {
	return &JWTService{
		CurrentSecret: []byte(secret),
		OldSecrets:    make([][]byte, 0),
		cfg:           cfg,
		auth:          auth,
	}
}

func (j *JWTService) RotateSecret(newSecret string) {
	j.mu.Lock()
	defer j.mu.Unlock()

	// Если уже есть старые ключи, удаляем самые старые
	if len(j.OldSecrets) >= j.cfg.JWT.OldKeysToKeep && j.cfg.JWT.OldKeysToKeep > 0 {
		j.OldSecrets = j.OldSecrets[1:]
	}

	// Добавляем текущий ключ в старые
	if j.cfg.JWT.OldKeysToKeep > 0 {
		j.OldSecrets = append(j.OldSecrets, j.CurrentSecret)
	}

	j.CurrentSecret = []byte(newSecret)
}

func (j *JWTService) GenerateJWT(userID int, username, role string) (string, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()

	claims := jwt.MapClaims{
		"user_id":  userID,
		"username": username,
		"role":     role,
		"exp":      time.Now().Add(j.cfg.JWT.TTL).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.CurrentSecret)
}

func generateRandomSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate random secret: " + err.Error())
	}
	return base64.StdEncoding.EncodeToString(b)
}

func (j *JWTService) ParseJWT(tokenString string) (jwt.MapClaims, error) {
	if claims, ok := j.auth.TokenCache.Get(tokenString); ok {
		return claims.(jwt.MapClaims), nil
	}

	claims, err := j.parseWithSecret(tokenString, j.CurrentSecret)
	if err == nil {
		j.auth.TokenCache.Set(tokenString, claims)
		return claims, nil
	}

	j.mu.RLock()
	defer j.mu.RUnlock()

	for _, secret := range j.OldSecrets {
		claims, err := j.parseWithSecret(tokenString, secret)
		if err == nil {
			j.auth.TokenCache.Set(tokenString, claims)
			return claims, nil
		}
	}

	return nil, errors.New("no valid secret found for token")
}

func (j *JWTService) parseWithSecret(tokenString string, secret []byte) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return secret, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("cannot parse claims")
	}
	return claims, nil
}
