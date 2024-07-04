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
