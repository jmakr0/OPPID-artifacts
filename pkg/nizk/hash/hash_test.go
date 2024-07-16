package hash

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	"testing"
)

func TestHashCircuit(t *testing.T) {
	hashProof, err := Setup()
	if err != nil {
		t.Fatal(err)
	}

	assert := test.NewAssert(t)
	field := ecc.BLS12_381.ScalarField()

	w, err := hashProof.NewWitness([]byte("secret X"), []byte("secret Y"), []byte("public preimage segment"))
	if err != nil {
		t.Fatal(err)
	}

	errProof := test.IsSolved(&Circuit{}, w.assignment, field)
	assert.NoError(errProof)
}

func TestHashCircuitWithManipulatedHash(t *testing.T) {
	hashProof, err := Setup()
	if err != nil {
		t.Fatal(err)
	}

	assert := test.NewAssert(t)
	field := ecc.BLS12_381.ScalarField()

	w, err := hashProof.NewWitness([]byte("secret X"), []byte("secret Y"), []byte("public preimage segment"))
	if err != nil {
		t.Fatal(err)
	}

	w.assignment.Image[0] = uints.NewU8(0xFF) // Manipulate the first byte of the Image

	errProof := test.IsSolved(&Circuit{}, w.assignment, field)
	assert.Error(errProof)
}

func TestHashCircuitWithManipulatedPreImage(t *testing.T) {
	hashProof, err := Setup()
	if err != nil {
		t.Fatal(err)
	}

	assert := test.NewAssert(t)
	field := ecc.BLS12_381.ScalarField()

	w, err := hashProof.NewWitness([]byte("secret X"), []byte("secret Y"), []byte("public preimage segment"))
	if err != nil {
		t.Fatal(err)
	}

	w.assignment.PreimagePub[0] = uints.NewU8(0xFF) // Manipulate the first byte of the public preimage part

	errProof := test.IsSolved(&Circuit{}, w.assignment, field)
	assert.Error(errProof)
}

func TestHashKeyGen(t *testing.T) {
	sha256Proof, err := Setup()
	if err != nil {
		t.Fatal(err)
	}

	_, _, errKGen := sha256Proof.KeyGen()
	if errKGen != nil {
		t.Fatal(errKGen)
	}
}

func TestHashProveVerify(t *testing.T) {
	hashProof, err := Setup()
	if err != nil {
		t.Fatal(err)
	}

	pk, vk, errKGen := hashProof.KeyGen()
	if errKGen != nil {
		t.Fatal(errKGen)
	}

	sharedInput := []byte("public preimage segment")

	witness, errW := hashProof.NewWitness([]byte("secret X"), []byte("secret Y"), sharedInput)
	if errW != nil {
		t.Fatal(errW)
	}

	proof, errP := hashProof.Prove(witness, pk)
	if errP != nil {
		t.Fatal(errP)
	}

	//pubWitness, errPW := witness.witness.Public()
	pubWitness, errPW := hashProof.NewPublicWitness(sharedInput, witness.image)
	if errPW != nil {
		t.Fatal(errPW)
	}

	isValid := hashProof.Verify(proof, pubWitness, vk)
	//isValid := hashProof.Verify(proof, PublicWitness{pubWitness}, vk)
	if !isValid {
		t.Fatal("invalid proof, expected proof to be valid")
	}
}
