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
	currentSecret []byte
	oldSecrets    [][]byte
	mu            sync.RWMutex
	cfg           *Config
}

func NewJWTService(secret string, cfg *Config) *JWTService {
	return &JWTService{
		currentSecret: []byte(secret),
		oldSecrets:    make([][]byte, 0),
		cfg:           cfg,
	}
}

func (j *JWTService) RotateSecret(newSecret string) {
	j.mu.Lock()
	defer j.mu.Unlock()

	j.oldSecrets = append(j.oldSecrets, j.currentSecret)
	j.currentSecret = []byte(newSecret)

	// Оставляем только необходимое количество старых ключей
	if len(j.oldSecrets) > j.cfg.JWT.OldKeysToKeep {
		j.oldSecrets = j.oldSecrets[len(j.oldSecrets)-j.cfg.JWT.OldKeysToKeep:]
	}
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
	return token.SignedString(j.currentSecret)
}

func generateRandomSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate random secret: " + err.Error())
	}
	return base64.StdEncoding.EncodeToString(b)
}

func (j *JWTService) ParseJWT(tokenString string) (jwt.MapClaims, error) {
	claims, err := j.parseWithSecret(tokenString, j.currentSecret)
	if err == nil {
		return claims, nil
	}

	j.mu.RLock()
	defer j.mu.RUnlock()

	for _, secret := range j.oldSecrets {
		claims, err := j.parseWithSecret(tokenString, secret)
		if err == nil {
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
