package oidc

import (
	"crypto/rand"
	"testing"
)

func TestOIDC_ResponseAndVerify(t *testing.T) {
	oidc, err := Setup(2048)
	if err != nil {
		t.Fatalf("Failed to create OIDC instance: %s", err)
	}

	rid := []byte("Test-RP")
	uid := []byte("alice.doe@idp.com")
	var ctx [16]byte
	var sid [8]byte

	_, _ = rand.Read(ctx[:])
	_, _ = rand.Read(sid[:])

	tk, err := oidc.Response(rid, uid, ctx[:], sid[:])
	if err != nil {
		t.Fatalf("Failed to create response: %s", err)
	}

	isValid := oidc.Verify(rid, tk.ppid, ctx[:], sid[:], tk.Sigma)
	if !isValid {
		t.Fatalf("Failed to verify response: %s", err)
	}
}

func TestOIDC_ResponseAndVerify_InvalidInputs(t *testing.T) {
	oidc, err := Setup(2048)
	if err != nil {
		t.Fatalf("Failed to create OIDC instance: %s", err)
	}

	rid := []byte("Test-RP")
	uid := []byte("alice.doe@idp.com")
	var ctx [16]byte
	var sid [8]byte

	_, _ = rand.Read(ctx[:])
	_, _ = rand.Read(sid[:])

	tk, err := oidc.Response(rid, uid, ctx[:], sid[:])
	if err != nil {
		t.Fatalf("Failed to create response: %s", err)
	}

	// Modify one byte of the sign to simulate an invalid sign
	tk.Sigma[0] ^= 0xFF

	isValid := oidc.Verify(rid, tk.ppid, ctx[:], sid[:], tk.Sigma)
	if isValid {
		t.Fatalf("Expected verification to fail for tampered sign")
	}
}
