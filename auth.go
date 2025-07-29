package access

import (
	"sync"
	"time"
)

type Authenticator struct {
	JwtService        *JWTService
	PasswordHasher    *PasswordHasher
	permissionsConfig *PermissionsConfig
	configMu          sync.RWMutex
	cfg               *Config

	// Кэши
	TokenCache      *memoryCache
	passwordCache   *memoryCache
	permissionCache *memoryCache
}

func NewAuthenticator(configPath string) (*Authenticator, error) {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return nil, err
	}

	auth := &Authenticator{
		cfg: cfg,
	}

	// Инициализируем кэши из конфига
	auth.TokenCache = NewCache(cfg.Cache.TokenTTL)
	auth.passwordCache = NewCache(cfg.Cache.PasswordTTL)
	auth.permissionCache = NewCache(cfg.Cache.PermissionTTL)

	// Инициализация сервисов с передачей auth
	auth.JwtService = NewJWTService(cfg.JWT.Secret, cfg, auth)
	auth.PasswordHasher = NewPasswordHasher(cfg.Password.Cost, auth)

	if err := auth.LoadPermissions(cfg.Permissions.Path); err != nil {
		return nil, err
	}

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
