package nizk

import (
	PC "OPPID/internal/commit/pedersen"
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
		t.Error("randomized signature Sig1 is nil")
	}

	if randSig.randSig.Sig2 == nil {
		t.Error("randomized signature Sig2 is nil")
	}

	// Ensure that randomization has altered the signature
	if sig.Sig1.IsEqual(randSig.randSig.Sig1) {
		t.Error("randomization did not change Sig1")
	}

	if sig.Sig2.IsEqual(randSig.randSig.Sig2) {
		t.Error("randomization did not change Sig2")
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
//	ps, _ := PS.New()
//	pc, _ := PC.New()
//
//	msg := []byte("Test")
//
//	sig, _ := ps.Sign(msg)
//	com, opening, _ := pc.Commit(msg)
//
//	witnesses := &Witnesses{
//		Msg:     msg,
//		Sig:     sig,
//		Opening: opening,
//	}
//
//	pubInput := &PublicInputs{
//		PSParams: ps,
//		PCParams: pc,
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
//	psSig := &ps.Signature{
//		Sig1: new(GG.G1).Random(),
//		Sig2: new(GG.G1).Random(),
//	}
//	opening := &pedersen.Opening{O: new(GG.Scalar).Random()}
//
//	witnesses := &Witnesses{
//		Msg:     msg,
//		Sig:     psSig,
//		Opening: opening,
//	}
//
//	// Mock PublicInputs
//	psParams := &ps.Params{
//		G: new(GG.G2).Random(),
//		Y: new(GG.G2).Random(),
//		X: new(GG.G2).Random(),
//	}
//	pcParams := &pedersen.Params{
//		G: new(GG.G1).Random(),
//		H: new(GG.G1).Random(),
//	}
//	com := &pedersen.Commitment{
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
