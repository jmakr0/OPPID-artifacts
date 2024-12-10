package com

import (
	PC "OPPID/pkg/oppid/commit/pc"
	"testing"
	"time"
)

func BenchmarkPCGenProof(b *testing.B) {
	pc := PC.Setup(nil)

	msg := []byte("test")
	com, opn := pc.Commit(msg)

	pubInput := &PublicInput{pc, &com}
	witness := &Witness{msg, &opn}

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		Prove(pubInput, witness)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkPCProofVerify(b *testing.B) {
	pc := PC.Setup(nil)

	msg := []byte("test")
	com, opn := pc.Commit(msg)

	pubInput := &PublicInput{pc, &com}
	witness := &Witness{msg, &opn}

	pi := Prove(pubInput, witness)

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		isValid := Verify(pubInput, pi)
		if !isValid {
			b.Fatal("verification failed")
		}
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}
