package access

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	JWT struct {
		Secret         string        `yaml:"secret"`           // Начальный (резервный) JWT-secret
		RotationPeriod time.Duration `yaml:"rotation_period"`  // Период ротации ключей
		TTL            time.Duration `yaml:"ttl"`              // Время жизни токена
		OldKeysToKeep  int           `yaml:"old_keys_to_keep"` // Сколько старых ключей оставлять
	} `yaml:"jwt"`

	Permissions struct {
		Path string `yaml:"path"` //Путь до файла с мапой ролей и их разрешениями
	} `yaml:"permissions"`

	Password struct {
		Cost int `yaml:"cost"` //Сложность хэширования пароля, оптимальное значение - 12. Больше информации в тестах
	} `yaml:"password"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
