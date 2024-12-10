package oidc

import (
	"testing"
)

func TestOIDCResponseAndVerify(t *testing.T) {
	oidc := Setup()
	isk, ipk := oidc.KeyGen()

	rid := []byte("Test-RID")
	uid := []byte("alice.doe@idp.com")
	ctx := []byte("Test-CTX")
	sid := []byte("Test-SID")

	tk := oidc.Response(isk, rid, uid, ctx, sid)

	isValid := oidc.Verify(ipk, rid, ctx, sid, tk)
	if !isValid {
		t.Fatalf("Token is not valid")
	}
}

func TestOIDCResponseAndVerifyInvalidInputs(t *testing.T) {
	oidc := Setup()
	isk, ipk := oidc.KeyGen()

	rid := []byte("Test-RID")
	uid := []byte("alice.doe@idp.com")
	ctx := []byte("Test-CTX")
	sid := []byte("Test-SID")

	tk := oidc.Response(isk, rid, uid, ctx, sid)

	// Modify one byte of the sign to simulate an invalid sign
	tk.sig[0] ^= 0xFF

	isValid := oidc.Verify(ipk, rid, ctx, sid, tk)
	if isValid {
		t.Fatalf("Expected verification to fail for tampered sign")
	}
}
