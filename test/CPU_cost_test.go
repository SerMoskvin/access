package access_test

import (
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestBCryptCost(t *testing.T) {
	file, err := os.Create("cost_result.txt")
	if err != nil {
		t.Fatalf("Failed to create results file: %v", err)
	}
	defer file.Close()

	fmt.Fprintln(file, "BCrypt Cost Benchmark Results")
	fmt.Fprintln(file, "============================")

	for cost := 4; cost <= 16; cost++ {
		start := time.Now()
		_, err := bcrypt.GenerateFromPassword([]byte("testpassword"), cost)
		duration := time.Since(start)

		if err != nil {
			t.Errorf("Cost %d failed: %v", cost, err)
			continue
		}

		result := fmt.Sprintf("Cost %2d: %v", cost, duration)

		t.Log(result)

		fmt.Fprintln(file, result)
	}

	msg := "Benchmark completed. Results saved to cost_result.txt"
	t.Log(msg)
	fmt.Fprintln(file, "\n"+msg)
}
