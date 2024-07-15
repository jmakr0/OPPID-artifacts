package ppoidc

import (
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
	nonceRP := Nonce("Test nonce RP")

	_, err := ppoidc.Init(ipk, uid, cert, nonceRP)
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
}
