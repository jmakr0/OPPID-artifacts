package oidc

import (
	"crypto/rand"
	"testing"
	"time"
)

func BenchmarkOIDCResponse(b *testing.B) {
	oidc := Setup()
	isk, _ := oidc.KeyGen()

	rid := []byte("Test-RP")
	uid := []byte("alice.doe@idp.com")

	var ctx [16]byte
	_, _ = rand.Read(ctx[:])

	var sid [8]byte
	_, _ = rand.Read(sid[:])

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		oidc.Response(isk, rid, uid, ctx[:], sid[:])
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkOIDCVerify(b *testing.B) {
	oidc := Setup()
	isk, ipk := oidc.KeyGen()

	rid := []byte("Test-RP")
	uid := []byte("alice.doe@idp.com")

	var ctx [16]byte
	_, _ = rand.Read(ctx[:])

	var sid [8]byte
	_, _ = rand.Read(sid[:])

	tk := oidc.Response(isk, rid, uid, ctx[:], sid[:])

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		isValid := oidc.Verify(ipk, rid, tk.ppid, ctx[:], sid[:], tk)
		if !isValid {
			b.Fatalf("Failed to verify response")
		}
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}
