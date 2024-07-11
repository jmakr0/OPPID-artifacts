package hash

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	"testing"
)

func TestSHA256Circuit(t *testing.T) {
	assert := test.NewAssert(t)
	field := ecc.BLS12_381.ScalarField()

	inputStr := "Hello world!"
	var input [MaxInputLength]byte
	copy(input[:], inputStr)

	digest := sha256.Sum256(input[:])
	fmt.Printf("%v\n", hex.EncodeToString(digest[:]))

	var preImage [MaxInputLength]uints.U8
	var output [32]uints.U8
	for i := 0; i < MaxInputLength; i++ {
		preImage[i] = uints.NewU8(input[i])
	}
	for i, d := range digest {
		output[i] = uints.NewU8(d)
	}
	assignment := &SHA256Circuit{preImage, output}

	err := test.IsSolved(&SHA256Circuit{}, assignment, field)
	assert.NoError(err)
}

func TestSHA256CircuitWithManipulatedHash(t *testing.T) {
	assert := test.NewAssert(t)
	field := ecc.BLS12_381.ScalarField()

	inputStr := "Hello world!"
	var input [MaxInputLength]byte
	copy(input[:], inputStr)

	digest := sha256.Sum256(input[:])
	digest[0] ^= 0xFF // Manipulate the first byte of the digest
	fmt.Printf("%v\n", hex.EncodeToString(digest[:]))

	var preImage [MaxInputLength]uints.U8
	var output [32]uints.U8
	for i := 0; i < MaxInputLength; i++ {
		preImage[i] = uints.NewU8(input[i])
	}
	for i, d := range digest {
		output[i] = uints.NewU8(d)
	}
	assignment := &SHA256Circuit{preImage, output}

	err := test.IsSolved(&SHA256Circuit{}, assignment, field)
	assert.Error(err)
}

func TestSHA256CircuitWithManipulatedPreImage(t *testing.T) {
	assert := test.NewAssert(t)
	field := ecc.BLS12_381.ScalarField()

	inputStr := "Hello world!"
	var input [MaxInputLength]byte
	copy(input[:], inputStr)

	digest := sha256.Sum256(input[:])
	fmt.Printf("%v\n", hex.EncodeToString(digest[:]))

	var preImage [MaxInputLength]uints.U8
	var output [32]uints.U8
	for i := 0; i < MaxInputLength; i++ {
		preImage[i] = uints.NewU8(input[i])
	}
	preImage[0] = uints.NewU8(42) // Manipulate the first byte of the input
	for i, d := range digest {
		output[i] = uints.NewU8(d)
	}
	assignment := &SHA256Circuit{preImage, output}

	err := test.IsSolved(&SHA256Circuit{}, assignment, field)
	assert.Error(err)
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

	witness, errW := sha256Proof.NewWitness("Hello world")
	if errW != nil {
		t.Fatal(errW)
	}

	proof, pubWitness, errP := sha256Proof.Prove(witness, pk)
	if errP != nil {
		t.Fatal(errP)
	}

	isValid, errV := sha256Proof.Verify(proof, pubWitness, vk)
	if errV != nil {
		t.Fatal(errV)
	}
	if !isValid {
		t.Fatal("invalid proof, expected proof to be valid")
	}
}
