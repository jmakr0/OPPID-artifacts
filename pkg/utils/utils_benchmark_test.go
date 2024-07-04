package utils

import (
	GG "github.com/cloudflare/circl/ecc/bls12381"
	"testing"
	"time"
)

func BenchmarkHashToScalar(b *testing.B) {
	data := make([]byte, 32) // Example data of 32 bytes
	dst := []byte("example dst")

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		HashToScalar(data, dst)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkGenerateRandomScalar(b *testing.B) {
	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		GenerateRandomScalar()
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkAddScalars(b *testing.B) {
	s1 := GenerateRandomScalar()
	s2 := GenerateRandomScalar()

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		AddScalars(s1, s2)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkMulScalars(b *testing.B) {
	s1 := GenerateRandomScalar()
	s2 := GenerateRandomScalar()

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		MulScalars(s1, s2)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkGenG1Point(b *testing.B) {
	g := GG.G1Generator()
	s := GenerateRandomScalar()

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		GenerateG1Point(s, g)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkAddG1Point(b *testing.B) {
	g1 := GG.G1Generator()
	g2 := GenerateG1Point(GenerateRandomScalar(), g1)

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		AddG1Points(g1, g2)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkGenG2Point(b *testing.B) {
	g := GG.G2Generator()
	s := GenerateRandomScalar()

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		GenerateG2Point(s, g)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkAddG2Point(b *testing.B) {
	g1 := GG.G2Generator()
	g2 := GenerateG2Point(GenerateRandomScalar(), g1)

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		AddG2Points(g1, g2)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkPairing(b *testing.B) {
	g1 := GG.G1Generator()
	g2 := GG.G2Generator()

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		GG.Pair(g1, g2)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}
