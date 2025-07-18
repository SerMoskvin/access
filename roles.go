package access

import (
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

type RolePermissions struct {
	Role           string    `yaml:"role"`
	Sections       []Section `yaml:"sections"`
	OwnRecordsOnly bool      `yaml:"own_records_only"`
}

type Section struct {
	Name     string `yaml:"name"`
	URL      string `yaml:"url"`
	CanRead  bool   `yaml:"can_read"`
	CanWrite bool   `yaml:"can_write"`
}

type PermissionsConfig struct {
	Roles map[string]RolePermissions `yaml:"roles"`
}

var (
	permissionsConfig *PermissionsConfig
	configOnce        sync.Once
)

// LoadPermissions загружает конфиг из YAML-файла
func LoadPermissions(path string) (*PermissionsConfig, error) {
	var cfg PermissionsConfig

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// GetPermissions возвращает конфиг (инициализирует его один раз)
func GetPermissions(path string) (*PermissionsConfig, error) {
	var err error
	configOnce.Do(func() {
		permissionsConfig, err = LoadPermissions(path)
	})
	return permissionsConfig, err
}
