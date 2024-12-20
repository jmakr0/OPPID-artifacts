package other

import (
	"OPPID-artifacts/protocol/other/aifzkp"
	"testing"
	"time"
)

func setupAIFZkPBenchmark() (*aifzkp.PublicParams, []byte, []byte, []byte, []byte, *aifzkp.PrivateKey, *aifzkp.PublicKey, aifzkp.Credential, aifzkp.UsrOpening, aifzkp.UsrCommitment) {
	aifZkp := aifzkp.Setup()
	isk, ipk := aifZkp.KeyGen()

	rid := []byte("Test-RID")
	uid := []byte("alice.doe@idp.com")
	ctx := []byte("Test-CTX")
	sid := []byte("Test-SID")

	cred := aifZkp.Register(isk, rid)

	orid, crid := aifZkp.Init(rid)

	return aifZkp, rid, uid, ctx, sid, isk, ipk, cred, orid, crid
}

func BenchmarkAIFZKPRegister(b *testing.B) {
	aifZkp, rid, _, _, _, isk, _, _, _, _ := setupAIFZkPBenchmark()
	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		aifZkp.Register(isk, rid)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkAIFZKPInit(b *testing.B) {
	aifZkp, rid, _, _, _, _, _, _, _, _ := setupAIFZkPBenchmark()
	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		aifZkp.Init(rid)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkAIFZKPRequest(b *testing.B) {
	aifZkp, rid, _, _, sid, _, ipk, cred, orid, crid := setupAIFZkPBenchmark()
	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		aifZkp.Request(ipk, rid, cred, crid, orid, sid)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkAIFZKPResponse(b *testing.B) {
	aifZkp, rid, uid, ctx, sid, isk, ipk, cred, orid, crid := setupAIFZkPBenchmark()
	auth := aifZkp.Request(ipk, rid, cred, crid, orid, sid)
	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		_, err := aifZkp.Response(isk, auth, crid, uid, ctx, sid)
		if err != nil {
			b.Fatalf("Error at response: %v", err)
		}
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkAIFZKPFinalize(b *testing.B) {
	aifZkp, rid, uid, ctx, sid, isk, ipk, cred, orid, crid := setupAIFZkPBenchmark()

	auth := aifZkp.Request(ipk, rid, cred, crid, orid, sid)
	tk, _ := aifZkp.Response(isk, auth, crid, uid, ctx, sid)

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		_, err := aifZkp.Finalize(ipk, rid, uid, ctx, sid, crid, orid, tk)
		if err != nil {
			b.Fatalf("Error at finalization: %v", err)
		}
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkAIFZKPVerify(b *testing.B) {
	aifZkp, rid, uid, ctx, sid, isk, ipk, cred, orid, crid := setupAIFZkPBenchmark()

	auth := aifZkp.Request(ipk, rid, cred, crid, orid, sid)
	tk, _ := aifZkp.Response(isk, auth, crid, uid, ctx, sid)
	ftk, _ := aifZkp.Finalize(ipk, rid, uid, ctx, sid, crid, orid, tk)

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		isValid := aifZkp.Verify(ipk, rid, uid, ctx, sid, ftk)
		if !isValid {
			b.Fatalf("verification did not succeed")
		}
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}
