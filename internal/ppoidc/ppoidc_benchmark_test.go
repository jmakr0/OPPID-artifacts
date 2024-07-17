package ppoidc

import (
	"crypto/rand"
	"testing"
	"time"
)

func setupBenchmark(b *testing.B) (*PublicParams, *PrivateKey, *PublicKey, UserId, ClientIDBinding, Nonce) {
	ppoidc, err := Setup()
	if err != nil {
		b.Fatal(err)
	}
	isk, ipk := ppoidc.KeyGen()

	uid := UserId("Test ID")
	name := ClientName("Test ID")
	ruri := RedirectUri("Test redirect URI")

	cert := ppoidc.Register(isk, name, ruri)

	var nonceRP Nonce
	_, _ = rand.Read(nonceRP[:])

	return ppoidc, isk, ipk, uid, cert, nonceRP
}

func BenchmarkInit(b *testing.B) {
	ppoidc, _, ipk, uid, cert, nonceRP := setupBenchmark(b)
	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		_, _, err := ppoidc.Init(ipk, uid, cert, nonceRP)
		if err != nil {
			b.Fatalf("Init failed: %v", err)
		}
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkResponse(b *testing.B) {
	ppoidc, isk, ipk, uid, cert, nonceRP := setupBenchmark(b)

	ctx := []byte("context")
	sid := []byte("sessionID")

	req, _, _ := ppoidc.Init(ipk, uid, cert, nonceRP)

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		_, err := ppoidc.Response(isk, uid, req, ctx, sid)
		if err != nil {
			b.Fatalf("Response returned an error: %v", err)
		}
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkVerify(b *testing.B) {
	ppoidc, isk, ipk, uid, cert, nonceRP := setupBenchmark(b)

	ctx := []byte("context")
	sid := []byte("sessionID")

	req, st, _ := ppoidc.Init(ipk, uid, cert, nonceRP)
	tk, _ := ppoidc.Response(isk, uid, req, ctx, sid)

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		isValid := ppoidc.Verify(ipk, cert.id, st, tk)
		if !isValid {
			b.Fatalf("Verify returned false for a valid token")
		}
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}
