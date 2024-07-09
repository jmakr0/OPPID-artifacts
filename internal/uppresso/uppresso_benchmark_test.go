package uppresso

import (
	"OPPID/pkg/utils"
	GG "github.com/cloudflare/circl/ecc/bls12381"
	"testing"
	"time"
)

func setupBenchmark() (*PublicParams, *GG.Scalar, []byte, []byte, *PrivateKey, *PublicKey, CertRP) {
	uppresso := Setup()
	isk, ipk := uppresso.KeyGen()

	id := []byte("test-RP")
	idU := utils.GenerateRandomScalar()

	enPt := []byte("endpoint")
	ctx := []byte("context")
	sid := []byte("session-id")

	cert := uppresso.Register(isk, id, enPt)

	return uppresso, idU, ctx, sid, isk, ipk, cert
}

func BenchmarkInit(b *testing.B) {
	uppresso, _, _, _, _, ipk, cert := setupBenchmark()
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

func BenchmarkRequest(b *testing.B) {
	uppresso, _, _, _, _, ipk, cert := setupBenchmark()
	_, t, _ := uppresso.Init(ipk, &cert)

	start := time.Now()
	for i := 0; i < b.N; i++ {
		uppresso.Request(cert.idRP, t)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkResponse(b *testing.B) {
	uppresso, idU, ctx, sid, isk, ipk, cert := setupBenchmark()
	uPidRP, _, _ := uppresso.Init(ipk, &cert)

	start := time.Now()
	for i := 0; i < b.N; i++ {
		uppresso.Response(isk, uPidRP, idU, ctx, sid)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}

func BenchmarkVerify(b *testing.B) {
	uppresso, idU, ctx, sid, isk, ipk, cert := setupBenchmark()

	uPidRP, t, _ := uppresso.Init(ipk, &cert)
	rpPidRP := uppresso.Request(cert.idRP, t)
	token := uppresso.Response(isk, uPidRP, idU, ctx, sid)

	start := time.Now()
	for i := 0; i < b.N; i++ {
		uppresso.Verify(ipk, rpPidRP, t, ctx, sid, token)
	}
	elapsed := time.Since(start)
	b.ReportMetric(float64(elapsed.Milliseconds())/float64(b.N), "ms/op")
}
