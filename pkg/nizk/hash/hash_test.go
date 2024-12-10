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

	circuitX, circuitY, circuitSharedInput, circuitImage, _ := BuildCircuitInputs([]byte("nonce X"), []byte("nonce Y"), []byte("shared public input"))

	witness, err := hashProof.NewWitness(circuitX, circuitY, circuitSharedInput, circuitImage)
	if err != nil {
		t.Fatal(err)
	}

	errProof := test.IsSolved(&Circuit{}, witness.assignment, field)
	assert.NoError(errProof)
}

func TestHashCircuitWithManipulatedImage(t *testing.T) {
	hashProof, err := Setup()
	if err != nil {
		t.Fatal(err)
	}

	assert := test.NewAssert(t)
	field := ecc.BLS12_381.ScalarField()

	circuitX, circuitY, circuitSharedInput, circuitImage, _ := BuildCircuitInputs([]byte("nonce X"), []byte("nonce Y"), []byte("shared public input"))

	witness, err := hashProof.NewWitness(circuitX, circuitY, circuitSharedInput, circuitImage)
	if err != nil {
		t.Fatal(err)
	}

	witness.assignment.Image[0] = uints.NewU8(0xFF) // Manipulate the first byte of the Image

	errProof := test.IsSolved(&Circuit{}, witness.assignment, field)
	assert.Error(errProof)
}

func TestHashCircuitWithManipulatedSharedInput(t *testing.T) {
	hashProof, err := Setup()
	if err != nil {
		t.Fatal(err)
	}

	assert := test.NewAssert(t)
	field := ecc.BLS12_381.ScalarField()

	sharedInput := []byte("shared public input")
	x := []byte("nonce X")
	y := []byte("nonce Y")

	circuitX, circuitY, circuitSharedInput, circuitImage, _ := BuildCircuitInputs(x, y, sharedInput)
	witness, err := hashProof.NewWitness(circuitX, circuitY, circuitSharedInput, circuitImage)
	if err != nil {
		t.Fatal(err)
	}

	witness.assignment.SharedInput[0] = uints.NewU8(0xFF) // Manipulate the first byte of the public preimage part

	errProof := test.IsSolved(&Circuit{}, witness.assignment, field)
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

	circuitX, circuitY, circuitSharedInput, circuitImage, _ := BuildCircuitInputs([]byte("nonce X"), []byte("nonce Y"), []byte("shared public input"))

	witness, errW := hashProof.NewWitness(circuitX, circuitY, circuitSharedInput, circuitImage)
	if errW != nil {
		t.Fatal(errW)
	}

	proof, errP := hashProof.Prove(witness, pk)
	if errP != nil {
		t.Fatal(errP)
	}

	pubWitness, errPW := hashProof.NewPublicWitness(circuitSharedInput, circuitImage)
	if errPW != nil {
		t.Fatal(errPW)
	}

	isValid := hashProof.Verify(proof, pubWitness, vk)
	if !isValid {
		t.Fatal("invalid proof, expected proof to be valid")
	}
}
