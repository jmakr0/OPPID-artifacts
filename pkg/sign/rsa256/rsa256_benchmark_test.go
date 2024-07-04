package rsa256

import (
	"testing"
	"time"
)

func BenchmarkRSASign(b *testing.B) {
	rsa := Setup(2048)
	sk, _ := rsa.KeyGen()

	msg := []byte("Hello, World!")

	b.ResetTimer()
	// Run the benchmark
	start := time.Now()
	for i := 0; i < b.N; i++ {
		rsa.Sign(sk, msg)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkRSAVerify(b *testing.B) {
	rsa := Setup(2048)
	sk, pk := rsa.KeyGen()

	msg := []byte("Hello, World!")
	sig := rsa.Sign(sk, msg)

	b.ResetTimer()
	// Run the benchmark
	start := time.Now()
	for i := 0; i < b.N; i++ {
		isValid := rsa.Verify(pk, msg, sig)
		if !isValid {
			b.Fatalf("Expected signature to be valid")
		}
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}
