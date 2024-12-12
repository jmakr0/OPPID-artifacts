package sig

import (
	PS "OPPID-artifacts/pkg/oppid/sign/ps"
	"testing"
	"time"
)

func BenchmarkPSGenProof(b *testing.B) {
	ps := PS.Setup(nil)
	sk, pk := ps.KeyGen()
	msg := []byte("test")

	sig := ps.Sign(sk, msg)

	publicInput := PublicInput{ps, pk}
	witness := Witness{msg, &sig}

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		Prove(publicInput, witness)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkPSProofVerify(b *testing.B) {
	ps := PS.Setup(nil)
	sk, pk := ps.KeyGen()
	msg := []byte("test")

	sig := ps.Sign(sk, msg)

	pubInput := PublicInput{ps, pk}
	witness := Witness{msg, &sig}

	proof := Prove(pubInput, witness)

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		isValid := Verify(pubInput, proof)
		if !isValid {
			b.Fatalf("verify fail")
		}
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}
