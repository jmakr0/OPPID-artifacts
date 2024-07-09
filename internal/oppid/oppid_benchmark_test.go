package oppid

import (
	"testing"
	"time"
)

func setupBenchmark() (*PublicParams, []byte, []byte, []byte, []byte, *PrivateKey, *PublicKey, Credential, UsrOpening, UsrCommitment, Auth, Token, FinalizedToken, PairwisePseudonymousIdentifier) {
	oppid := Setup()
	isk, ipk := oppid.KeyGen()

	rid := []byte("Test-RID")
	uid := []byte("alice.doe@idp.com")
	ctx := []byte("Test-CTX")
	sid := []byte("Test-SID")

	cred := oppid.Register(isk, rid)
	orid, crid := oppid.Init(rid)
	auth, _ := oppid.Request(ipk, rid, cred, crid, orid, sid)
	tk, _ := oppid.Response(isk, auth, crid, uid, ctx, sid)
	ftk, ppid, _ := oppid.Finalize(ipk, rid, ctx, sid, crid, orid, tk)

	return oppid, rid, uid, ctx, sid, isk, ipk, cred, orid, crid, auth, tk, ftk, ppid
}

func BenchmarkOPPIDRegister(b *testing.B) {
	oppid, rid, _, _, _, isk, _, _, _, _, _, _, _, _ := setupBenchmark()
	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		oppid.Register(isk, rid)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkOPPIDInit(b *testing.B) {
	oppid, rid, _, _, _, _, _, _, _, _, _, _, _, _ := setupBenchmark()
	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		oppid.Init(rid)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkOPPIDRequest(b *testing.B) {
	oppid, rid, _, _, sid, _, ipk, cred, orid, crid, _, _, _, _ := setupBenchmark()
	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		_, err := oppid.Request(ipk, rid, cred, crid, orid, sid)
		if err != nil {
			b.Fatal(err)
		}
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkOPPIDResponse(b *testing.B) {
	oppid, _, uid, ctx, sid, isk, _, _, _, crid, auth, _, _, _ := setupBenchmark()
	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		_, err := oppid.Response(isk, auth, crid, uid, ctx, sid)
		if err != nil {
			b.Fatal(err)
		}
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkOPPIDFinalize(b *testing.B) {
	oppid, rid, _, ctx, sid, _, ipk, _, orid, crid, _, tk, _, _ := setupBenchmark()
	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		_, _, err := oppid.Finalize(ipk, rid, ctx, sid, crid, orid, tk)
		if err != nil {
			b.Fatal(err)
		}
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkOPPIDVerify(b *testing.B) {
	oppid, rid, _, ctx, sid, _, ipk, _, _, _, _, _, ftk, ppid := setupBenchmark()
	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		isValid := oppid.Verify(ipk, rid, ppid, ctx, sid, ftk)
		if !isValid {
			b.Fatalf("oppid verify failed")
		}
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}
