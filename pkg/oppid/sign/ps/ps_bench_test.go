package ps

import (
	"testing"
	"time"
)

func BenchmarkPSSign(b *testing.B) {
	ps := Setup(nil)
	sk, _ := ps.KeyGen()

	msg := []byte("Hello, World!")

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		ps.Sign(sk, msg)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkPSVerify(b *testing.B) {
	ps := Setup(nil)
	sk, pk := ps.KeyGen()

	msg := []byte("Hello, World!")
	sig := ps.Sign(sk, msg)

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		isValid := ps.Verify(pk, msg, sig)
		if !isValid {
			b.Fatalf("Expected signature to be valid")
		}
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}
