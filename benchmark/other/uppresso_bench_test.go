package other

import (
	"OPPID/pkg/oppid/utils"
	UPPRESSO "OPPID/protocol/other/uppresso"
	GG "github.com/cloudflare/circl/ecc/bls12381"
	"testing"
	"time"
)

func setupUPPRESSOBenchmark() (*UPPRESSO.PublicParams, *GG.Scalar, []byte, []byte, *UPPRESSO.PrivateKey, *UPPRESSO.PublicKey, UPPRESSO.CertRP) {
	uppresso := UPPRESSO.Setup()
	isk, ipk := uppresso.KeyGen()

	id := []byte("test-RP")
	idU := utils.GenerateRandomScalar()

	enPt := []byte("endpoint")
	ctx := []byte("context")
	sid := []byte("session-id")

	cert := uppresso.Register(isk, id, enPt)

	return uppresso, idU, ctx, sid, isk, ipk, cert
}

func BenchmarkUPPRESSOInit(b *testing.B) {
	uppresso, _, _, _, _, ipk, cert := setupUPPRESSOBenchmark()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		_, _, err := uppresso.Init(ipk, &cert)
		if err != nil {
			b.Fatal(err)
		}
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkUPPRESSORequest(b *testing.B) {
	uppresso, _, _, _, _, ipk, cert := setupUPPRESSOBenchmark()
	_, t, _ := uppresso.Init(ipk, &cert)

	start := time.Now()
	for i := 0; i < b.N; i++ {
		uppresso.Request(cert.Id, t)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkUPPRESSOResponse(b *testing.B) {
	uppresso, idU, ctx, sid, isk, ipk, cert := setupUPPRESSOBenchmark()
	uPidRP, _, _ := uppresso.Init(ipk, &cert)

	start := time.Now()
	for i := 0; i < b.N; i++ {
		uppresso.Response(isk, uPidRP, idU, ctx, sid)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkUPPRESSOVerify(b *testing.B) {
	uppresso, idU, ctx, sid, isk, ipk, cert := setupUPPRESSOBenchmark()

	uPidRP, t, _ := uppresso.Init(ipk, &cert)
	rpPidRP := uppresso.Request(cert.Id, t)
	token := uppresso.Response(isk, uPidRP, idU, ctx, sid)

	start := time.Now()
	for i := 0; i < b.N; i++ {
		uppresso.Verify(ipk, rpPidRP, t, ctx, sid, token)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}
