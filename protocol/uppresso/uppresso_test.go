package uppresso

import (
	"OPPID/pkg/utils"
	"testing"
)

func TestSetup(t *testing.T) {
	uppresso := Setup()
	if uppresso == nil {
		t.Fatal("Setup returned nil")
	}
	if uppresso.rsa == nil {
		t.Fatal("Setup did not initialize RSA parameters")
	}
}

func TestKeyGen(t *testing.T) {
	uppresso := Setup()
	isk, ipk := uppresso.KeyGen()
	if isk == nil || ipk == nil {
		t.Fatal("KeyGen returned nil")
	}
	if isk.rsaSk == nil || ipk.rsaPk == nil {
		t.Fatal("KeyGen did not generate valid RSA keys")
	}
}

func TestRegister(t *testing.T) {
	uppresso := Setup()
	isk, _ := uppresso.KeyGen()
	id := []byte("test-id")
	enPt := []byte("endpoint")
	cert := uppresso.Register(isk, id, enPt)
	if cert.Id == nil {
		t.Fatal("Register did not generate a valid idRP")
	}
	if cert.sig == nil {
		t.Fatal("Register did not generate a valid signature")
	}
}

func TestInit(t *testing.T) {
	uppresso := Setup()
	isk, ipk := uppresso.KeyGen()
	id := []byte("test-id")
	enPt := []byte("endpoint")
	cert := uppresso.Register(isk, id, enPt)

	pidRP, _, err := uppresso.Init(ipk, &cert)
	if err != nil {
		t.Fatalf("Init returned an error: %v", err)
	}
	if pidRP == nil || t == nil {
		t.Fatal("Init did not generate valid pidRP or t")
	}
}

func TestRequest(t *testing.T) {
	uppresso := Setup()
	sk, pk := uppresso.KeyGen()
	id := []byte("test-id")
	enPt := []byte("endpoint")
	cert := uppresso.Register(sk, id, enPt)
	_, r, _ := uppresso.Init(pk, &cert)
	pidRP := uppresso.Request(cert.Id, r)
	if pidRP == nil {
		t.Fatal("Request did not generate a valid PidRP")
	}
}

func TestResponse(t *testing.T) {
	uppresso := Setup()
	sk, pk := uppresso.KeyGen()
	id := []byte("test-id")
	enPt := []byte("endpoint")
	cert := uppresso.Register(sk, id, enPt)
	pidRP, _, _ := uppresso.Init(pk, &cert)
	idU := utils.GenerateRandomScalar()
	ctx := []byte("context")
	sid := []byte("session-id")
	token := uppresso.Response(sk, pidRP, idU, ctx, sid)
	if token.pidU == nil {
		t.Fatal("Response did not generate a valid pidU")
	}
	if token.sig == nil {
		t.Fatal("Response did not generate a valid signature")
	}
}

func TestVerify(t *testing.T) {
	uppresso := Setup()
	sk, pk := uppresso.KeyGen()
	id := []byte("test-id")
	enPt := []byte("endpoint")
	cert := uppresso.Register(sk, id, enPt)
	pidRP, r, _ := uppresso.Init(pk, &cert)
	rpPidRP := uppresso.Request(cert.Id, r)
	idU := utils.GenerateRandomScalar()
	ctx := []byte("context")
	sid := []byte("session-id")
	token := uppresso.Response(sk, pidRP, idU, ctx, sid)
	acct := uppresso.Verify(pk, rpPidRP, r, ctx, sid, token)
	if acct == nil {
		t.Fatal("Verify failed")
	}
}
