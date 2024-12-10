package comsig

import (
	PC "OPPID/pkg/oppid/commit/pc"
	PS "OPPID/pkg/oppid/sign/ps"
	"testing"
	"time"
)

func BenchmarkPCPSGenProof(b *testing.B) {
	ps := PS.Setup([]byte(dstStr))
	pc := PC.Setup([]byte(dstStr))

	sk, pk := ps.KeyGen()

	msg := []byte("Test")

	sig := ps.Sign(sk, msg)
	com, opn := pc.Commit(msg)

	witness := Witnesses{msg, &sig, &opn}
	pubInput := PublicInputs{pk, pc, &com}

	aux := []byte("auxiliary data")

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		Prove(witness, pubInput, aux, []byte(dstStr))
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkPCPSProofVerify(b *testing.B) {
	ps := PS.Setup([]byte(dstStr))
	pc := PC.Setup([]byte(dstStr))

	sk, pk := ps.KeyGen()

	msg := []byte("Test")

	sig := ps.Sign(sk, msg)
	com, opn := pc.Commit(msg)

	witness := Witnesses{msg, &sig, &opn}
	pubInput := PublicInputs{pk, pc, &com}

	aux := []byte("auxiliary data")

	proof := Prove(witness, pubInput, aux, []byte(dstStr))

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		isValid := Verify(proof, pubInput, aux)
		if !isValid {
			b.Fatalf("verify fail")
		}
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}
