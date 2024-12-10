package comsig

import (
	PC "OPPID/pkg/commit/pc"
	PS "OPPID/pkg/sign/ps"
	"OPPID/pkg/utils"
	"testing"
)

func TestProveVerify(t *testing.T) {
	ps := PS.Setup([]byte(dstStr))
	pc := PC.Setup([]byte(dstStr))

	sk, pk := ps.KeyGen()

	msg := []byte("Test")

	sig := ps.Sign(sk, msg)
	com, opn := pc.Commit(msg)

	witness := Witnesses{msg, &sig, &opn}
	pubInput := PublicInputs{pk, pc, &com}

	aux := []byte("auxiliary data")
	proof := Prove(witness, pubInput, aux, []byte(dstStr))

	isValid := Verify(proof, pubInput, aux)

	if !isValid {
		t.Error("proof is not valid")
	}
}

func TestVerifyInvalidProof(t *testing.T) {
	ps := PS.Setup([]byte(dstStr))
	pc := PC.Setup([]byte(dstStr))

	sk, pk := ps.KeyGen()

	msg := []byte("Test")

	sig := ps.Sign(sk, msg)
	com, opn := pc.Commit(msg)

	witness := Witnesses{msg, &sig, &opn}
	pubInput := PublicInputs{pk, pc, &com}

	aux := []byte("auxiliary data")
	proof := Prove(witness, pubInput, aux, []byte(dstStr))

	// Modify the proof
	proof.r1 = utils.GenerateRandomScalar()

	isValid := Verify(proof, pubInput, aux)

	if isValid {
		t.Error("invalid proof was accepted as valid")
	}
}
