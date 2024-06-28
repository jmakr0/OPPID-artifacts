package rsa256

import (
	"testing"
	"time"
)

func BenchmarkRSASign(b *testing.B) {
	// Create a new RSAWrapper with a 2048-bit key
	rsa256, err := New(2048)
	if err != nil {
		b.Fatalf("Failed to create RSA wrapper: %s", err)
	}

	message := []byte("Hello, World!")

	b.ResetTimer()

	// Run the benchmark
	start := time.Now()
	for i := 0; i < b.N; i++ {
		_, err := rsa256.Sign(message)
		if err != nil {
			b.Fatalf("Failed to sign message: %s", err)
		}
	}

	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

// BenchmarkRSAVerify benchmarks the verification operation
func BenchmarkRSAVerify(b *testing.B) {
	// Create a new RSAWrapper with a 2048-bit key
	rsa256, err := New(2048)
	if err != nil {
		b.Fatalf("Failed to create RSA wrapper: %s", err)
	}

	message := []byte("Hello, World!")

	// Sign the message
	signature, err := rsa256.Sign(message)
	if err != nil {
		b.Fatalf("Failed to sign message: %s", err)
	}

	b.ResetTimer()

	// Run the benchmark
	start := time.Now()
	for i := 0; i < b.N; i++ {
		isValid := rsa256.Verify(message, signature)
		if !isValid {
			b.Fatalf("Failed to verify sign: %s", err)
		}
	}

	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}
