package hash

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	"testing"
)

func TestSHA256Circuit(t *testing.T) {
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

func TestSHA256CircuitWithManipulatedHash(t *testing.T) {
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

func TestSHA256CircuitWithManipulatedPreImage(t *testing.T) {
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

func TestSHA256KeyGen(t *testing.T) {
	sha256Proof, err := Setup()
	if err != nil {
		t.Fatal(err)
	}

	_, _, errKGen := sha256Proof.KeyGen()
	if errKGen != nil {
		t.Fatal(errKGen)
	}
}

func TestSHA256ProveVerify(t *testing.T) {
	sha256Proof, err := Setup()
	if err != nil {
		t.Fatal(err)
	}

	pk, vk, errKGen := sha256Proof.KeyGen()
	if errKGen != nil {
		t.Fatal(errKGen)
	}

	witness, errW := sha256Proof.NewWitness([]byte("secret X"), []byte("secret Y"), []byte("public preimage segment"))
	if errW != nil {
		t.Fatal(errW)
	}

	proof, pubWitness, errP := sha256Proof.Prove(witness, pk)
	if errP != nil {
		t.Fatal(errP)
	}

	isValid := sha256Proof.Verify(proof, pubWitness, vk)
	if !isValid {
		t.Fatal("invalid proof, expected proof to be valid")
	}
}
