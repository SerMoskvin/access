package access_test

import (
	"fmt"
	"os"
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

// TestResult - структура для хранения результатов тестирования
type TestResult struct {
	Name       string
	FirstCall  time.Duration
	TotalTime  time.Duration
	AvgPerCall time.Duration
}

var performanceResults []TestResult

const performanceIterations = 1000000

func TestJWT_CachePerformance(t *testing.T) {
	auth, err := access.NewAuthenticator("./test_config.yml")
	assert.NoError(t, err)

	// Генерация тестового токена
	token, err := auth.JwtService.GenerateJWT(1, "user", "admin")
	assert.NoError(t, err)

	// Тест 1: С кешем (повторные вызовы)
	t.Run("With cache (repeated calls)", func(t *testing.T) {
		auth.TokenCache.Clear()

		start := time.Now()
		_, err := auth.JwtService.ParseJWT(token)
		assert.NoError(t, err)
		firstCall := time.Since(start)

		start = time.Now()
		for i := 0; i < performanceIterations; i++ {
			_, _ = auth.JwtService.ParseJWT(token)
		}
		totalTime := time.Since(start)

		performanceResults = append(performanceResults, TestResult{
			Name:       "With cache",
			FirstCall:  firstCall,
			TotalTime:  totalTime,
			AvgPerCall: totalTime / performanceIterations,
		})
	})

	// Тест 2: Без кеша
	t.Run("Without cache", func(t *testing.T) {
		start := time.Now()
		for i := 0; i < performanceIterations; i++ {
			auth.TokenCache.Clear()
			_, _ = auth.JwtService.ParseJWT(token)
		}
		totalTime := time.Since(start)

		performanceResults = append(performanceResults, TestResult{
			Name:       "Without cache",
			FirstCall:  0,
			TotalTime:  totalTime,
			AvgPerCall: totalTime / performanceIterations,
		})
	})

	// Тест 3: Смешанные токены
	t.Run("Mixed tokens (10 unique)", func(t *testing.T) {
		tokens := make([]string, 10)
		for i := range tokens {
			tokens[i], _ = auth.JwtService.GenerateJWT(i+1, "user", "admin")
		}

		start := time.Now()
		for i := 0; i < performanceIterations; i++ {
			token := tokens[i%len(tokens)]
			_, _ = auth.JwtService.ParseJWT(token)
		}
		totalTime := time.Since(start)

		performanceResults = append(performanceResults, TestResult{
			Name:       "Mixed tokens",
			FirstCall:  0,
			TotalTime:  totalTime,
			AvgPerCall: totalTime / performanceIterations,
		})
	})

	printPerformanceResults()
}

func printPerformanceResults() {
	resultStr := "\n=== JWT Cache Performance Results ===\n"
	resultStr += fmt.Sprintf("Iterations: %d\n", performanceIterations)
	resultStr += "+-----------------+----------------+----------------+----------------+\n"
	resultStr += "|      Test       |   First Call   |   Total Time   |  Avg Per Call  |\n"
	resultStr += "+-----------------+----------------+----------------+----------------+\n"

	for _, r := range performanceResults {
		firstCall := "-"
		if r.FirstCall > 0 {
			firstCall = fmt.Sprintf("%10v", r.FirstCall.Round(time.Microsecond))
		}

		resultStr += fmt.Sprintf("| %-15s | %14s | %14s | %14s |\n",
			r.Name,
			firstCall,
			r.TotalTime.Round(time.Millisecond),
			r.AvgPerCall.Round(time.Nanosecond))
	}

	resultStr += "+-----------------+----------------+----------------+----------------+\n"

	fmt.Println(resultStr)

	if err := os.WriteFile("jwt_cache_performance.txt", []byte(resultStr), 0644); err != nil {
		fmt.Printf("Failed to write results: %v\n", err)
	} else {
		fmt.Println("Results saved to jwt_cache_performance.txt")
	}
}
