package aifzkp

import (
	"crypto/rand"
	"testing"
)

func TestAIFZKPRegister(t *testing.T) {
	aifZkp := Setup()
	isk, _ := aifZkp.KeyGen()

	cred := aifZkp.Register(isk, []byte("Test-RID"))
	if cred.sig.One == nil || cred.sig.Two == nil {
		t.Errorf("Failed to register AIFZKP")
	}
}

func TestAIFZKPInit(t *testing.T) {
	aifZkp := Setup()
	aifZkp.KeyGen()

	orid, crid := aifZkp.Init([]byte("Test-RID"))
	if orid.opening.Scalar == nil || crid.com.Element == nil {
		t.Errorf("Failed to initialize request")
	}
}

func TestAIFZKPRequestResponse(t *testing.T) {
	aifZkp := Setup()
	isk, ipk := aifZkp.KeyGen()

	rid := []byte("Test-RID")

	uid := []byte("alice.doe@idp.com")

	var ctx [16]byte
	_, _ = rand.Read(ctx[:])

	var sid [8]byte
	_, _ = rand.Read(sid[:])

	cred := aifZkp.Register(isk, rid)

	orid, crid := aifZkp.Init([]byte("Test-RID"))

	auth := aifZkp.Request(ipk, rid, cred, crid, orid, sid[:])
	_, err := aifZkp.Response(isk, auth, crid, uid, ctx[:], sid[:])
	if err != nil {
		t.Errorf("Expected the authentication request to succeed")
	}

}
