package sig

import (
	PS "OPPID/pkg/sign/ps"
	"testing"
)

func TestRandomizeSignature(t *testing.T) {
	ps := PS.Setup(nil)
	sk, _ := ps.KeyGen()

	sig := ps.Sign(sk, []byte("Test"))

	_, randSig := Randomize(&sig)

	if randSig.One == nil {
		t.Error("randomized signature One is nil")
	}

	if randSig.Two == nil {
		t.Error("randomized signature Two is nil")
	}

	// Ensure that randomization has altered the signature
	if sig.One.IsEqual(randSig.One) {
		t.Error("randomization did not change sig1")
	}

	if sig.Two.IsEqual(randSig.Two) {
		t.Error("randomization did not change sig2")
	}
}

func TestProveVerify(t *testing.T) {
	ps := PS.Setup(nil)
	sk, pk := ps.KeyGen()
	msg := []byte("test")

	sig := ps.Sign(sk, msg)

	pubInput := PublicInput{ps, pk}
	witness := Witness{msg, &sig}

	proof := Prove(pubInput, witness)

	isValid := Verify(pubInput, proof)
	if !isValid {
		t.Errorf("Verify(%v, %v) returned %v", pubInput, proof, isValid)
	}
}
