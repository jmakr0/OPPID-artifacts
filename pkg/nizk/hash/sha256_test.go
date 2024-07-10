package hash

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	"os"
	"testing"
)

const (
	circuitFileName = "circuit.r1cs.bin"
	pkFileName      = "pk.bin"
	vkFileName      = "vk.bin"
)

func loadCS(file string) (constraint.ConstraintSystem, error) {
	buf, _ := os.Open(file)
	cs := groth16.NewCS(ecc.BLS12_381)
	_, err := cs.ReadFrom(buf)
	if err != nil {
		return nil, err
	}
	return cs, nil
}

func loadProvingAndVerifyingKeys(pkFile, vkFile string) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	bufPk, _ := os.Open(pkFile)
	pk := groth16.NewProvingKey(ecc.BLS12_381)
	_, errPk := pk.ReadFrom(bufPk)
	if errPk != nil {
		return nil, nil, errPk
	}
	bufPk.Close()

	bufVk, _ := os.Open(vkFile)
	vk := groth16.NewVerifyingKey(ecc.BLS12_381)
	_, errVk := pk.ReadFrom(bufVk)
	if errVk != nil {
		return nil, nil, errVk
	}
	bufVk.Close()

	return pk, vk, nil
}

func storeCS(cs constraint.ConstraintSystem, csFile string) error {
	var buf bytes.Buffer
	_, errBuf := cs.WriteTo(&buf)
	if errBuf != nil {
		return errBuf
	}
	errFile := os.WriteFile(csFile, buf.Bytes(), 0644)
	if errFile != nil {
		return errFile
	}
	return nil
}

func storeProvingAndVerifyingKeys(pk groth16.ProvingKey, pkFile string, vk groth16.VerifyingKey, vkFile string) error {
	var bufPk bytes.Buffer
	_, errPk := pk.WriteRawTo(&bufPk)
	if errPk != nil {
		return errPk
	}
	errPkFile := os.WriteFile(pkFile, bufPk.Bytes(), 0644)
	if errPkFile != nil {
		return errPkFile
	}

	var bufVk bytes.Buffer
	_, errVk := vk.WriteRawTo(&bufVk)
	if errVk != nil {
		return errVk
	}
	errVkFile := os.WriteFile(vkFile, bufVk.Bytes(), 0644)
	if errVkFile != nil {
		return errVkFile
	}

	return nil
}

func compileCS(c *SHA256Circuit) (constraint.ConstraintSystem, error) {
	cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, c)
	if err != nil {
		return nil, err
	}
	return cs, nil
}

func keyGen(cs constraint.ConstraintSystem) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		fmt.Println("error setting up keys:", err)
		return nil, nil, err
	}
	return pk, vk, nil
}

func setup() (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {
	if _, err := os.Stat(circuitFileName); err == nil { // Load circuit and keys from files
		cs, csErr := loadCS(circuitFileName)
		if csErr != nil {
			return nil, nil, nil, csErr
		}
		pk, vk, kErr := loadProvingAndVerifyingKeys(pkFileName, vkFileName)
		if kErr != nil {
			return nil, nil, nil, kErr
		}
		return cs, pk, vk, nil
	} else if errors.Is(err, os.ErrNotExist) { // Compile circuit and keys
		var circuit SHA256Circuit
		cs, csErr := compileCS(&circuit)
		if csErr != nil {
			return nil, nil, nil, csErr
		}
		pk, vk, kErr := keyGen(cs)
		if kErr != nil {
			return nil, nil, nil, kErr
		}
		//// store circuit and keys
		//errStoreCS := storeCS(cs, circuitFileName)
		//if errStoreCS != nil {
		//	return nil, nil, nil, errStoreCS
		//}
		//errStoreKeys := storeProvingAndVerifyingKeys(pk, pkFileName, vk, vkFileName)
		//if errStoreKeys != nil {
		//	return nil, nil, nil, errStoreKeys
		//}
		return cs, pk, vk, nil
	}
	return nil, nil, nil, nil
}

//cs, pk, vk, err := setup()
//if err != nil {
//	t.Fatal(err)
//}
//
//witness, _ := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
//
////fmt.Println("witness:", witness)
//
//// Create a proof
//proof, err := groth16.Prove(cs, pk, witness)
//if err != nil {
//	t.Fatalf("Error creating proof: %v", err)
//}
//
//// Verify the proof
//publicWitness, _ := witness.Public()
//
//err = groth16.Verify(proof, vk, publicWitness)
//if err != nil {
//	fmt.Println("Proof verification failed:", err)
//} else {
//	fmt.Println("Proof verification succeeded")
//}

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
