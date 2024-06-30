package commit_sig

import (
	PC "OPPID/internal/commit/pc"
	PS "OPPID/internal/sign/ps"
	"testing"
)

func TestRandomizePSSignature(t *testing.T) {
	ps, _ := PS.New()
	sig, _ := ps.Sign([]byte("Test"))

	// Call randomizePSSignature
	randSig := randomizePSSignature(sig)

	// Check that the signature is not nil
	if randSig.randSig == nil {
		t.Error("randomized signature is nil")
	}

	if randSig.randSig.Sig1 == nil {
		t.Error("randomized signature One is nil")
	}

	if randSig.randSig.Sig2 == nil {
		t.Error("randomized signature Two is nil")
	}

	// Ensure that randomization has altered the signature
	if sig.One.IsEqual(randSig.randSig.Sig1) {
		t.Error("randomization did not change One")
	}

	if sig.Two.IsEqual(randSig.randSig.Sig2) {
		t.Error("randomization did not change Two")
	}
}

func TestNewVerify(t *testing.T) {
	ps, _ := PS.New()
	pc, _ := PC.New()

	msg := []byte("Test")

	sig, _ := ps.Sign(msg)
	com, opening, _ := pc.Commit(msg)

	witnesses := &Witnesses{
		Msg:     msg,
		Sig:     sig,
		Opening: opening,
	}

	pubInput := &PublicInputs{
		PSParams: ps,
		PCParams: pc,
		Com:      com,
	}

	// Call New to generate the pi
	aux := []byte("auxiliary data")
	pi := New(witnesses, pubInput, aux)

	// Call Verify with the generated proof
	valid := Verify(pi, pubInput, aux)

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

	if !valid {
		t.Error("proof is not valid")
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
//	psParams := &sig.Params{
//		G: new(GG.G2).Random(),
//		Y: new(GG.G2).Random(),
//		X: new(GG.G2).Random(),
//	}
//	pcParams := &pc.Params{
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
