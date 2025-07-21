package access_test

import (
	"testing"
	"time"

	"github.com/SerMoskvin/access"
	"github.com/stretchr/testify/assert"
)

func TestMemoryCache(t *testing.T) {
	// Создаем кэш с маленьким TTL для тестов
	cache := access.NewCache(100 * time.Millisecond)

	t.Run("Set and Get", func(t *testing.T) {
		cache.Clear()
		cache.Set("key1", "value1")

		// Проверяем, что значение есть в кэше
		val, ok := cache.Get("key1")
		assert.True(t, ok)
		assert.Equal(t, "value1", val)
	})

	t.Run("Get non-existent key", func(t *testing.T) {
		cache.Clear()
		val, ok := cache.Get("nonexistent")
		assert.False(t, ok)
		assert.Nil(t, val)
	})

	t.Run("Expiration", func(t *testing.T) {
		cache.Clear()
		cache.Set("key2", "value2")

		// Проверяем, что значение есть в кэше
		val, ok := cache.Get("key2")
		assert.True(t, ok)
		assert.Equal(t, "value2", val)

		// Ждем, пока значение истечет
		time.Sleep(150 * time.Millisecond)

		// Проверяем, что значение больше нет в кэше
		val, ok = cache.Get("key2")
		assert.False(t, ok)
		assert.Nil(t, val)
	})

	t.Run("Concurrent access", func(t *testing.T) {
		cache.Clear()
		const workers = 10
		const iterations = 100

		// Запускаем несколько горутин для конкурентного доступа
		done := make(chan struct{})
		for i := 0; i < workers; i++ {
			go func(id int) {
				for j := 0; j < iterations; j++ {
					key := "key" + string(rune(id))
					cache.Set(key, j)
					_, _ = cache.Get(key)
				}
				done <- struct{}{}
			}(i)
		}

		// Ждем завершения всех горутин
		for i := 0; i < workers; i++ {
			<-done
		}
	})
}
