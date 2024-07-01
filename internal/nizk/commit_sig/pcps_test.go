package commit_sig

import (
	PC "OPPID/internal/commit/pc"
	NIZK_PS "OPPID/internal/nizk/sig"
	PS "OPPID/internal/sign/ps"
	"testing"
)

func TestRandomizePSSignature(t *testing.T) {
	ps := PS.New("")
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
	ps := PS.New(DSTStr)
	pc := PC.New(DSTStr)

	msg := []byte("Test")

	sig := ps.Sign(msg)
	com, opening := pc.Commit(msg)

	w := &Witnesses{Msg: msg, Sig: sig, Opening: opening}

	p := &PublicInputs{PSParams: ps, PCParams: pc, Com: com}

	// Call New to generate the proof
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

	if pi.s1 == nil {
		t.Error("pi s1 is nil")
	}

	if pi.s2 == nil {
		t.Error("pi s2 is nil")
	}

	if pi.s3 == nil {
		t.Error("pi s3 is nil")
	}

	if !isValid {
		t.Error("proof is not isValid")
	}
}

//func TestVerify(t *testing.T) {
//	sig, _ := PS.New()
//	commit, _ := PC.New()
//
//	msg := []byte("Test")
//
//	sig, _ := sig.Sign(msg)
//	com, opening, _ := commit.Commit(msg)
//
//	witnesses := &Witnesses{
//		Msg:     msg,
//		Sig:     sig,
//		Opening: opening,
//	}
//
//	pubInput := &PublicInputs{
//		PSParams: sig,
//		PCParams: commit,
//		Com:      com,
//	}
//
//	// Call New to generate the proof
//	aux := []byte("auxiliary data")
//	proof := New(witnesses, pubInput, aux)
//
//	// Call Verify with the generated proof
//	valid := Verify(proof, pubInput, aux)
//
//	// Ensure the proof is valid
//	if !valid {
//		t.Error("proof is not valid")
//	}
//}

//func TestVerify_InvalidProof(t *testing.T) {
//	// Mock Witnesses
//	msg := []byte("test message")
//	psSig := &sig.Signature{
//		One: new(GG.G1).Random(),
//		Two: new(GG.G1).Random(),
//	}
//	opening := &pc.Opening{O: new(GG.Scalar).Random()}
//
//	witnesses := &Witnesses{
//		Msg:     msg,
//		Sig:     psSig,
//		Opening: opening,
//	}
//
//	// Mock PublicInputs
//	psParams := &sig.PS{
//		G: new(GG.G2).Random(),
//		Y: new(GG.G2).Random(),
//		X: new(GG.G2).Random(),
//	}
//	pcParams := &pc.PS{
//		G: new(GG.G1).Random(),
//		H: new(GG.G1).Random(),
//	}
//	com := &pc.Commitment{
//		C: new(GG.G1).Random(),
//	}
//
//	pubInput := &PublicInputs{
//		PSParams: psParams,
//		PCParams: pcParams,
//		Com:      com,
//	}
//
//	// Call New to generate the proof
//	aux := []byte("auxiliary data")
//	proof := New(witnesses, pubInput, aux)
//
//	// Modify the proof to make it invalid
//	proof.s1 = new(GG.Scalar).Random()
//
//	// Call Verify with the modified proof
//	valid := Verify(proof, pubInput, aux)
//
//	// Ensure the proof is invalid
//	if valid {
//		t.Error("invalid proof was accepted as valid")
//	}
//}
