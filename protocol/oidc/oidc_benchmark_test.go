package oidc

import (
	"crypto/rand"
	"testing"
	"time"
)

func BenchmarkOIDC_Response(b *testing.B) {
	oidc := New(2048)

	rid := []byte("Test-RP")
	uid := []byte("alice.doe@idp.com")
	var ctx [16]byte
	var sid [8]byte

	_, _ = rand.Read(ctx[:])
	_, _ = rand.Read(sid[:])

	b.ResetTimer()
	start := time.Now()

	for i := 0; i < b.N; i++ {
		oidc.Response(rid, uid, ctx[:], sid[:])
	}

	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkOIDC_Verify(b *testing.B) {
	oidc := New(2048)

	rid := []byte("Test-RP")
	uid := []byte("alice.doe@idp.com")
	var ctx [16]byte
	var sid [8]byte

	_, _ = rand.Read(ctx[:])
	_, _ = rand.Read(sid[:])

	tk := oidc.Response(rid, uid, ctx[:], sid[:])

	b.ResetTimer()
	start := time.Now()

	for i := 0; i < b.N; i++ {
		isValid := oidc.Verify(rid, tk.ppid, ctx[:], sid[:], tk.Sigma)
		if !isValid {
			b.Fatalf("Failed to verify response")
		}
	}

	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}
