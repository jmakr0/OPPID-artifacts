package oppid

import (
	"testing"
	"time"
)

func BenchmarkOPPIDRegister(b *testing.B) {
	oppid := Setup()
	isk, _ := oppid.KeyGen()
	rid := []byte("Test-RID")

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		oppid.Register(isk, rid)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkOPPIDInit(b *testing.B) {
	oppid := Setup()
	rid := []byte("Test-RID")

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		oppid.Init(rid)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkOPPIDRequest(b *testing.B) {
	oppid := Setup()
	_, pk := oppid.KeyGen()
	isk, _ := oppid.KeyGen()
	rid := []byte("Test-RID")
	cred := oppid.Register(isk, rid)
	orid, crid := oppid.Init(rid)
	sid := []byte("Test-SID")

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		oppid.Request(pk, rid, cred, crid, orid, sid)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkOPPIDResponse(b *testing.B) {
	oppid := Setup()
	isk, pk := oppid.KeyGen()
	rid := []byte("Test-RID")
	cred := oppid.Register(isk, rid)
	orid, crid := oppid.Init(rid)
	sid := []byte("Test-SID")
	auth, _ := oppid.Request(pk, rid, cred, crid, orid, sid)
	uid := []byte("Test-UID")
	ctx := []byte("Test-CTX")

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		oppid.Response(isk, auth, crid, uid, ctx, sid)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkOPPIDFinalize(b *testing.B) {
	oppid := Setup()
	isk, pk := oppid.KeyGen()
	rid := []byte("Test-RID")
	cred := oppid.Register(isk, rid)
	orid, crid := oppid.Init(rid)
	sid := []byte("Test-SID")
	auth, _ := oppid.Request(pk, rid, cred, crid, orid, sid)
	uid := []byte("Test-UID")
	ctx := []byte("Test-CTX")
	token, _ := oppid.Response(isk, auth, crid, uid, ctx, sid)

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		oppid.Finalize(pk, rid, ctx, sid, crid, orid, token)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkOPPIDVerify(b *testing.B) {
	oppid := Setup()
	isk, pk := oppid.KeyGen()
	rid := []byte("Test-RID")
	cred := oppid.Register(isk, rid)
	orid, crid := oppid.Init(rid)
	sid := []byte("Test-SID")
	auth, _ := oppid.Request(pk, rid, cred, crid, orid, sid)
	uid := []byte("Test-UID")
	ctx := []byte("Test-CTX")
	token, _ := oppid.Response(isk, auth, crid, uid, ctx, sid)
	finalToken, ppid, _ := oppid.Finalize(pk, rid, ctx, sid, crid, orid, token)

	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		oppid.Verify(pk, rid, ppid, ctx, sid, finalToken)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}
