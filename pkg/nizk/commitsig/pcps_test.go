package commitsig

import (
	PC "OPPID/pkg/commit/pc"
	NIZK_PS "OPPID/pkg/nizk/sig"
	PS "OPPID/pkg/sign/ps"
	"OPPID/pkg/utils"
	"testing"
)

func TestRandomizePSSignature(t *testing.T) {
	ps := PS.KeyGen("")
	sig := ps.Sign([]byte("Test"))

	// Call randomizePSSignature
	randSig := NIZK_PS.Randomize(sig)

	// Check that the signature is not nil
	if randSig.Sig == nil {
		t.Error("randomized signature is nil")
	}

	if randSig.Sig.One == nil {
		t.Error("randomized signature One is nil")
	}

	if randSig.Sig.Two == nil {
		t.Error("randomized signature Two is nil")
	}

	// Ensure that randomization has altered the signature
	if sig.One.IsEqual(randSig.Sig.One) {
		t.Error("randomization did not change sig1")
	}

	if sig.Two.IsEqual(randSig.Sig.Two) {
		t.Error("randomization did not change sig2")
	}
}

func TestNewVerify(t *testing.T) {
	ps := PS.KeyGen(DSTStr)
	pc := PC.Setup(DSTStr)

	msg := []byte("Test")

	sig := ps.Sign(msg)
	com, opening := pc.Commit(msg)

	w := &Witnesses{Msg: msg, Sig: sig, Opening: opening}
	p := &PublicInputs{PSParams: ps, PCParams: pc, Com: com}

	// Call KeyGen to generate the proof
	aux := []byte("auxiliary data")
	pi := New(w, p, aux)

	isValid := Verify(pi, p, aux)

	// Ensure pi is not nil and all fields are populated
	if pi == nil {
		t.Error("pi is nil")
	}

	if pi.sig == nil {
		t.Error("pi signature is nil")
	}

	if pi.a1 == nil {
		t.Error("pi a1 is nil")
	}

	if pi.a2 == nil {
		t.Error("pi a2 is nil")
	}

	if pi.r1 == nil {
		t.Error("pi r1 is nil")
	}

	if pi.r2 == nil {
		t.Error("pi r2 is nil")
	}

	if pi.r3 == nil {
		t.Error("pi r3 is nil")
	}

	if !isValid {
		t.Error("proof is not isValid")
	}
}

func TestVerify_InvalidProof(t *testing.T) {
	ps := PS.KeyGen(DSTStr)
	pc := PC.Setup(DSTStr)

	msg := []byte("Test")

	sig := ps.Sign(msg)
	com, opening := pc.Commit(msg)

	w := &Witnesses{Msg: msg, Sig: sig, Opening: opening}
	p := &PublicInputs{PSParams: ps, PCParams: pc, Com: com}

	// Call KeyGen to generate the proof
	aux := []byte("auxiliary data")
	proof := New(w, p, aux)

	// Modify the proof to make it invalid
	proof.r1 = utils.GenerateRandomScalar()

	// Call Verify with the modified proof
	isValid := Verify(proof, p, aux)

	// Ensure the proof is invalid
	if isValid {
		t.Error("invalid proof was accepted as valid")
	}
}
