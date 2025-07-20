package access

import (
	"sync"
	"time"
)

type Authenticator struct {
	JwtService        *JWTService
	passwordHasher    *PasswordHasher
	permissionsConfig *PermissionsConfig
	configMu          sync.RWMutex
	cfg               *Config
}

func NewAuthenticator(configPath string) (*Authenticator, error) {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return nil, err
	}

	auth := &Authenticator{
		JwtService:     NewJWTService(cfg.JWT.Secret, cfg),
		passwordHasher: NewPasswordHasher(cfg.Password.Cost),
		cfg:            cfg,
	}

	if err := auth.LoadPermissions(cfg.Permissions.Path); err != nil {
		return nil, err
	}

	// Запускаем ротацию ключей по таймеру
	if cfg.JWT.RotationPeriod > 0 {
		go auth.startKeyRotation()
	}

	return auth, nil
}

func (a *Authenticator) startKeyRotation() {
	ticker := time.NewTicker(a.cfg.JWT.RotationPeriod)
	defer ticker.Stop()

	for range ticker.C {
		newSecret := generateRandomSecret()
		a.JwtService.RotateSecret(newSecret)
	}
}

func (a *Authenticator) LoadPermissions(path string) error {
	cfg, err := GetPermissions(path)
	if err != nil {
		return err
	}

	a.configMu.Lock()
	defer a.configMu.Unlock()
	a.permissionsConfig = cfg
	return nil
}
