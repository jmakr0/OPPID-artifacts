package ppoidc

import (
	"crypto/rand"
	"testing"
)

func setupAndKeyGen(t *testing.T) (*PublicParams, *PrivateKey, *PublicKey) {
	ppoidc, err := Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	isk, ipk := ppoidc.KeyGen()

	return ppoidc, isk, ipk
}

func TestKeyGen(t *testing.T) {
	setupAndKeyGen(t)
}

func TestRegister(t *testing.T) {
	ppoidc, isk, _ := setupAndKeyGen(t)
	name := ClientName("Test ID")
	ruid := RedirectUri("Test redirect URI")
	ppoidc.Register(isk, name, ruid)
}

func TestInit(t *testing.T) {
	ppoidc, isk, ipk := setupAndKeyGen(t)

	uid := UserId("Test ID")
	name := ClientName("Test ID")
	ruid := RedirectUri("Test redirect URI")
	cert := ppoidc.Register(isk, name, ruid)

	var nonceRP Nonce
	_, _ = rand.Read(nonceRP[:])

	_, _, err := ppoidc.Init(ipk, uid, cert, nonceRP)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}

func TestResponse(t *testing.T) {
	ppoidc, isk, ipk := setupAndKeyGen(t)

	uid := UserId("Test ID")
	name := ClientName("Test ID")
	ruid := RedirectUri("Test redirect URI")
	cert := ppoidc.Register(isk, name, ruid)

	var nonceRP Nonce
	_, _ = rand.Read(nonceRP[:])

	req, _, _ := ppoidc.Init(ipk, uid, cert, nonceRP)
	ctx := []byte("context")
	sid := []byte("sessionID")

	_, err := ppoidc.Response(isk, uid, req, ctx, sid)
	if err != nil {
		t.Fatalf("Response returned an error: %v", err)
	}
}

func TestVerify(t *testing.T) {
	ppoidc, isk, ipk := setupAndKeyGen(t)

	uid := UserId("Test ID")
	name := ClientName("Test ID")
	ruid := RedirectUri("Test redirect URI")
	cert := ppoidc.Register(isk, name, ruid)

	var nonceRP Nonce
	_, _ = rand.Read(nonceRP[:])

	req, st, _ := ppoidc.Init(ipk, uid, cert, nonceRP)
	ctx := []byte("context")
	sid := []byte("sessionID")

	tk, _ := ppoidc.Response(isk, uid, req, ctx, sid)

	isValid := ppoidc.Verify(ipk, cert.id, st, tk)
	if !isValid {
		t.Fatalf("Verify returned false for a valid token")
	}
}
