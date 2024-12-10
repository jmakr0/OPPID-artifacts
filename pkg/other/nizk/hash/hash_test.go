package hash

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	"os"
	"testing"
	"time"
)

func getFileSizeInMB(filePath string) (float64, error) {
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return 0, err
	}

	fileSizeBytes := fileInfo.Size()

	sizeMB := float64(fileSizeBytes) / (1024 * 1024)
	return sizeMB, nil
}

func deleteFile(filePath string) {
	err := os.Remove(filePath)
	if err != nil {
		fmt.Printf("Error deleting file: %v\n", err)
	}
}

func TestCircuitMetadata(t *testing.T) {
	pp, err := Setup()
	if err != nil {
		t.Errorf("Error generating hash proof system: %v\n", err)
		return
	}
	startTime := time.Now()
	_, _, err = pp.KeyGen()
	if err != nil {
		t.Errorf("Error generating keys: %v\n", err)
		return
	}
	elapsedTime := time.Since(startTime)

	circuitSizeMB, err := getFileSizeInMB(circuitFileName)
	if err != nil {
		t.Errorf("Error getting circuit file size: %v\n", err)
		return
	}
	provingKeySizeMB, err := getFileSizeInMB(pkFileName)
	if err != nil {
		t.Errorf("Error getting proving key file size: %v\n", err)
		return
	}
	verificationKeySizeMB, err := getFileSizeInMB(vkFileName)
	if err != nil {
		t.Errorf("Error getting verification key file size: %v\n", err)
		return
	}

	t.Logf("Number of constraints: %v\n", pp.CS.GetNbConstraints())
	t.Logf("KeyGen took: %.2f seconds\n", elapsedTime.Seconds())
	t.Logf("Circuit size MB: %v\n", circuitSizeMB)
	t.Logf("Proving key size MB: %v\n", provingKeySizeMB)
	t.Logf("Verification key size MB: %v\n", verificationKeySizeMB)

	deleteFile(circuitFileName)
	deleteFile(pkFileName)
	deleteFile(vkFileName)
}

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
