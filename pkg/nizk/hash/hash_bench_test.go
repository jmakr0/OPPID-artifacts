package hash

import (
	"testing"
	"time"
)

func BenchmarkHashGenProof(b *testing.B) {
	hashProof, err := Setup()
	if err != nil {
		b.Fatal(err)
	}

	pk, _, errKGen := hashProof.KeyGen()
	if errKGen != nil {
		b.Fatal(errKGen)
	}

	circuitX, circuitY, circuitSharedInput, circuitImage, _ := BuildCircuitInputs([]byte("nonce X"), []byte("nonce Y"), []byte("shared public input"))

	witness, errW := hashProof.NewWitness(circuitX, circuitY, circuitSharedInput, circuitImage)
	if errW != nil {
		b.Fatal(errW)
	}

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		_, errP := hashProof.Prove(witness, pk)
		if errP != nil {
			b.Fatal(errP)
		}
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkHashProofVerify(b *testing.B) {
	hashProof, err := Setup()
	if err != nil {
		b.Fatal(err)
	}

	pk, vk, errKGen := hashProof.KeyGen()
	if errKGen != nil {
		b.Fatal(errKGen)
	}

	circuitX, circuitY, circuitSharedInput, circuitImage, _ := BuildCircuitInputs([]byte("nonce X"), []byte("nonce Y"), []byte("shared public input"))

	witness, errW := hashProof.NewWitness(circuitX, circuitY, circuitSharedInput, circuitImage)
	if errW != nil {
		b.Fatal(errW)
	}

	proof, errP := hashProof.Prove(witness, pk)
	if errP != nil {
		b.Fatal(errP)
	}
	pubWitness, errPW := hashProof.NewPublicWitness(circuitSharedInput, circuitImage)
	if errPW != nil {
		b.Fatal(errPW)
	}

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		isValid := hashProof.Verify(proof, pubWitness, vk)
		if !isValid {
			b.Fatal("invalid proof, expected proof to be valid")
		}
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}
