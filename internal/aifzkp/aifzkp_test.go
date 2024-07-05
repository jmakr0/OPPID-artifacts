package aifzkp

import "testing"

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
	_, _ = aifZkp.KeyGen()

	orid, crid := aifZkp.Init([]byte("Test-RID"))
	if orid.opening.Scalar == nil || crid.com.Element == nil {
		t.Errorf("Failed to initialize request")
	}
}
