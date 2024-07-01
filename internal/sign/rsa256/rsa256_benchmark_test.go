package rsa256

import (
	"testing"
	"time"
)

func BenchmarkRSASign(b *testing.B) {
	// Create a new RSAWrapper with a 2048-bit key
	rsa256 := New(2048)

	message := []byte("Hello, World!")

	b.ResetTimer()

	// Run the benchmark
	start := time.Now()
	for i := 0; i < b.N; i++ {
		rsa256.Sign(message)
	}

	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkRSAVerify(b *testing.B) {
	rsa256 := New(2048)

	message := []byte("Hello, World!")
	signature := rsa256.Sign(message)

	b.ResetTimer()

	// Run the benchmark
	start := time.Now()
	for i := 0; i < b.N; i++ {
		isValid := rsa256.Verify(message, signature)
		if !isValid {
			b.Fatalf("Expected signature to be valid")
		}
	}

	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}
