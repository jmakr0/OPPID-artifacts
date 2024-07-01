package oidc

import (
	"crypto/rand"
	"testing"
)

func TestOIDCResponseAndVerify(t *testing.T) {
	oidc := New(2048)

	rid := []byte("Test-RP")
	uid := []byte("alice.doe@idp.com")
	var ctx [16]byte
	var sid [8]byte

	_, _ = rand.Read(ctx[:])
	_, _ = rand.Read(sid[:])

	tk := oidc.Response(rid, uid, ctx[:], sid[:])

	isValid := oidc.Verify(rid, tk.ppid, ctx[:], sid[:], tk.Sigma)
	if !isValid {
		t.Fatalf("Token is not valid")
	}
}

func TestOIDCResponseAndVerifyInvalidInputs(t *testing.T) {
	oidc := New(2048)

	rid := []byte("Test-RP")
	uid := []byte("alice.doe@idp.com")
	var ctx [16]byte
	var sid [8]byte

	_, _ = rand.Read(ctx[:])
	_, _ = rand.Read(sid[:])

	tk := oidc.Response(rid, uid, ctx[:], sid[:])

	// Modify one byte of the sign to simulate an invalid sign
	tk.Sigma[0] ^= 0xFF

	isValid := oidc.Verify(rid, tk.ppid, ctx[:], sid[:], tk.Sigma)
	if isValid {
		t.Fatalf("Expected verification to fail for tampered sign")
	}
}
