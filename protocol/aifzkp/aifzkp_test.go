package aifzkp

import (
	"crypto/rand"
	"testing"
)

func generateContextAndSessionID() ([16]byte, [8]byte) {
	var ctx [16]byte
	_, _ = rand.Read(ctx[:])
	var sid [8]byte
	_, _ = rand.Read(sid[:])
	return ctx, sid
}

func TestAIFZKPRegister(t *testing.T) {
	aifZkp := Setup()
	isk, _ := aifZkp.KeyGen()

	cred := aifZkp.Register(isk, []byte("Test-RID"))
	if cred.sig.One == nil || cred.sig.Two == nil {
		t.Errorf("Failed to register AIFZKP: credential signature parts are nil")
	}
}

func TestAIFZKPInit(t *testing.T) {
	aifZkp := Setup()
	aifZkp.KeyGen()

	orid, crid := aifZkp.Init([]byte("Test-RID"))
	if orid.opening.Scalar == nil || crid.com.Element == nil {
		t.Errorf("Failed to initialize request: opening scalar or commitment element is nil")
	}
}

func TestAIFZKPRequestResponse(t *testing.T) {
	aifZkp := Setup()
	isk, ipk := aifZkp.KeyGen()

	rid := []byte("Test-RID")
	uid := []byte("alice.doe@idp.com")
	ctx, sid := generateContextAndSessionID()

	cred := aifZkp.Register(isk, rid)

	orid, crid := aifZkp.Init(rid)
	auth := aifZkp.Request(ipk, rid, cred, crid, orid, sid[:])
	_, err := aifZkp.Response(isk, auth, crid, uid, ctx[:], sid[:])
	if err != nil {
		t.Errorf("Expected the authentication request to succeed, but got error: %v", err)
	}
}

func TestAIFZKPFinVf(t *testing.T) {
	aifZkp := Setup()
	isk, ipk := aifZkp.KeyGen()

	rid := []byte("Test-RID")
	uid := []byte("alice.doe@idp.com")
	ctx, sid := generateContextAndSessionID()

	cred := aifZkp.Register(isk, rid)

	orid, crid := aifZkp.Init(rid)
	auth := aifZkp.Request(ipk, rid, cred, crid, orid, sid[:])

	tk, err := aifZkp.Response(isk, auth, crid, uid, ctx[:], sid[:])
	if err != nil {
		t.Errorf("Expected the authentication request to succeed, but got error: %v", err)
	}

	ftk, err := aifZkp.Finalize(ipk, rid, uid, ctx[:], sid[:], crid, orid, tk)
	if err != nil {
		t.Errorf("Expected token finalization to succeed, but got error: %v", err)
	}

	isValid := aifZkp.Verify(ipk, rid, uid, ctx[:], sid[:], ftk)
	if !isValid {
		t.Errorf("Expected the final verification to succeed, but the verification failed")
	}
}

func TestAIFZKPEdgeCases(t *testing.T) {
	aifZkp := Setup()
	isk, ipk := aifZkp.KeyGen()

	rid1 := []byte("Test-RID")
	rid2 := []byte("Test-RID")

	uid1 := []byte("alice.doe@idp.com")
	uid2 := []byte("bob.doe@idp.com")

	ctx1, sid1 := generateContextAndSessionID()
	ctx2, sid2 := generateContextAndSessionID()

	cred1 := aifZkp.Register(isk, rid1)
	cred2 := aifZkp.Register(isk, rid2)

	orid1, crid1 := aifZkp.Init(rid1)
	orid2, crid2 := aifZkp.Init(rid2)

	auth1 := aifZkp.Request(ipk, rid1, cred1, crid1, orid1, sid1[:])
	auth2 := aifZkp.Request(ipk, rid2, cred2, crid2, orid2, sid2[:])

	tk1, _ := aifZkp.Response(isk, auth1, crid1, uid1, ctx1[:], sid1[:])
	tk2, _ := aifZkp.Response(isk, auth2, crid2, uid2, ctx2[:], sid2[:])

	ftk1, _ := aifZkp.Finalize(ipk, rid1, uid1, ctx1[:], sid1[:], crid1, orid1, tk1)
	ftk2, _ := aifZkp.Finalize(ipk, rid2, uid2, ctx2[:], sid2[:], crid2, orid2, tk2)

	// Request/Response with mismatched session IDs
	_, err1 := aifZkp.Response(isk, auth1, crid1, uid1, ctx1[:], sid2[:])
	if err1 == nil {
		t.Errorf("Expected the authentication request to fail with mismatched session IDs, but it succeeded")
	}

	// Request/Response with mismatched authentication
	_, err2 := aifZkp.Response(isk, auth2, crid1, uid1, ctx1[:], sid1[:])
	if err2 == nil {
		t.Errorf("Expected the authentication request to fail with mismatched authentication, but it succeeded")
	}

	// Request/Response with mismatched commitment
	_, err3 := aifZkp.Response(isk, auth1, crid2, uid1, ctx1[:], sid1[:])
	if err3 == nil {
		t.Errorf("Expected the authentication request to fail with mismatched commitment, but it succeeded")
	}

	// Response/Finalization with mismatched user
	_, err4 := aifZkp.Finalize(ipk, rid1, uid2, ctx1[:], sid1[:], crid1, orid1, tk1)
	if err4 == nil {
		t.Errorf("Expected finalization to fail with mismatched user, but it succeeded")
	}

	// Response/Finalization with mismatched session
	_, err5 := aifZkp.Finalize(ipk, rid1, uid1, ctx1[:], sid2[:], crid1, orid1, tk1)
	if err5 == nil {
		t.Errorf("Expected finalization to fail with mismatched user, but it succeeded")
	}

	// Response/Finalization with mismatched opening
	_, err6 := aifZkp.Finalize(ipk, rid1, uid1, ctx1[:], sid1[:], crid1, orid2, tk1)
	if err6 == nil {
		t.Errorf("Expected finalization to fail with mismatched user, but it succeeded")
	}

	// Response/Finalization with mismatched token
	_, err7 := aifZkp.Finalize(ipk, rid1, uid1, ctx1[:], sid2[:], crid1, orid1, tk2)
	if err7 == nil {
		t.Errorf("Expected finalization to fail with mismatched user, but it succeeded")
	}

	// Verification with mismatched token
	isValid1 := aifZkp.Verify(ipk, rid1, uid1, ctx1[:], sid1[:], ftk2)
	if isValid1 {
		t.Errorf("Expected verification to fail with mismatched token, but it succeeded")
	}

	// Verification with mismatched session
	isValid2 := aifZkp.Verify(ipk, rid1, uid1, ctx1[:], sid2[:], ftk1)
	if isValid2 {
		t.Errorf("Expected verification to fail with mismatched session, but it succeeded")
	}
}
