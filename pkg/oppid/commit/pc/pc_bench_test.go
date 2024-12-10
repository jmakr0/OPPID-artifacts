package pc

import (
	"testing"
	"time"
)

func BenchmarkPCCommit(b *testing.B) {
	pc := Setup(nil)
	msg := []byte("test message")

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		pc.Commit(msg)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkPCOpen(b *testing.B) {
	pc := Setup(nil)
	msg := []byte("test message")

	c, o := pc.Commit(msg)

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		isValid := pc.Open(msg, c, o)
		if !isValid {
			b.Fatal("open failed")
		}
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}
