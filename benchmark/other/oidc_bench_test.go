package other

import (
	OIDC "OPPID-artifacts/protocol/other/oidc"
	"testing"
	"time"
)

func setupOIDCBenchmark() (*OIDC.PublicParams, []byte, []byte, []byte, []byte, *OIDC.PrivateKey, *OIDC.PublicKey) {
	oidc := OIDC.Setup()
	isk, ipk := oidc.KeyGen()

	rid := []byte("Test-RID")
	uid := []byte("alice.doe@idp.com")
	ctx := []byte("Test-CTX")
	sid := []byte("Test-SID")

	return oidc, rid, uid, ctx, sid, isk, ipk
}

func BenchmarkOIDCResponse(b *testing.B) {
	oidc, rid, uid, ctx, sid, isk, _ := setupOIDCBenchmark()
	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		oidc.Response(isk, rid, uid, ctx, sid)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkOIDCVerify(b *testing.B) {
	oidc, rid, uid, ctx, sid, isk, ipk := setupOIDCBenchmark()

	tk := oidc.Response(isk, rid, uid, ctx, sid)

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		isValid := oidc.Verify(ipk, rid, ctx, sid, tk)
		if !isValid {
			b.Fatalf("failed to verify response")
		}
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}
