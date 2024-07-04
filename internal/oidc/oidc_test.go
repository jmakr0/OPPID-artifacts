package oidc

import (
	"crypto/rand"
	"testing"
)

func TestOIDCResponseAndVerify(t *testing.T) {
	oidc := Setup()
	isk, ipk := oidc.KeyGen()

	rid := []byte("Test-RP")
	uid := []byte("alice.doe@idp.com")

	var ctx [16]byte
	_, _ = rand.Read(ctx[:])

	var sid [8]byte
	_, _ = rand.Read(sid[:])

	tk := oidc.Response(isk, rid, uid, ctx[:], sid[:])

	isValid := oidc.Verify(ipk, rid, tk.ppid, ctx[:], sid[:], tk)
	if !isValid {
		t.Fatalf("Token is not valid")
	}
}

func TestOIDCResponseAndVerifyInvalidInputs(t *testing.T) {
	oidc := Setup()
	isk, ipk := oidc.KeyGen()

	rid := []byte("Test-RP")
	uid := []byte("alice.doe@idp.com")

	var ctx [16]byte
	_, _ = rand.Read(ctx[:])

	var sid [8]byte
	_, _ = rand.Read(sid[:])

	tk := oidc.Response(isk, rid, uid, ctx[:], sid[:])

	// Modify one byte of the sign to simulate an invalid sign
	tk.sig[0] ^= 0xFF

	isValid := oidc.Verify(ipk, rid, tk.ppid, ctx[:], sid[:], tk)
	if isValid {
		t.Fatalf("Expected verification to fail for tampered sign")
	}
}
