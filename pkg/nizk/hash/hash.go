// The package provides a wrapper around Gnark tailored to our use case, enabling a proof system for hash-based
// statements as required by PPOIDC [1] (p. 7). Specifically, it proves statements of the form H(H(user_id||x)||y).

// References:
// [1] https://dl.acm.org/doi/10.1145/3320269.3384724

package hash

import (
	"bytes"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
	"os"
)

const (
	CircuitFileName = "circuit.r1cs.bin"
	PkFileName      = "proving_key.bin"
	VkFileName      = "verification_key.bin"
)

type PublicParams struct{ CS constraint.ConstraintSystem }

type ProvingKey struct{ key groth16.ProvingKey }
type VerifyingKey struct{ key groth16.VerifyingKey }

type Witness struct {
	assignment *Circuit // for testing
	witness    witness.Witness
}
type PublicWitness struct{ witness witness.Witness }

type Proof struct{ proof groth16.Proof }

func loadCS(csFilePath string) (constraint.ConstraintSystem, error) {
	csFile, err := os.Open(csFilePath)
	if err != nil {
		return nil, err
	}
	defer func(pkFile *os.File) {
		_ = pkFile.Close()
	}(csFile)

	var buf bytes.Buffer
	_, err = buf.ReadFrom(csFile)
	if err != nil {
		return nil, err
	}

	cs := groth16.NewCS(ecc.BLS12_381)
	_, err = cs.ReadFrom(&buf)
	if err != nil {
		return nil, err
	}

	return cs, nil
}

func loadKeys(pkFilePath, vkFilePath string) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	pkFile, err := os.Open(pkFilePath)
	if err != nil {
		return nil, nil, err
	}
	defer func(pkFile *os.File) {
		_ = pkFile.Close()
	}(pkFile)

	var buf bytes.Buffer
	_, err = buf.ReadFrom(pkFile)
	if err != nil {
		return nil, nil, err
	}

	pk := groth16.NewProvingKey(ecc.BLS12_381)
	_, err = pk.ReadFrom(&buf)
	if err != nil {
		return nil, nil, err
	}

	vkFile, err := os.Open(vkFilePath)
	if err != nil {
		return nil, nil, err
	}
	defer func(vkFile *os.File) {
		_ = vkFile.Close()
	}(vkFile)

	buf.Reset()
	_, err = buf.ReadFrom(vkFile)
	if err != nil {
		return nil, nil, err
	}

	vk := groth16.NewVerifyingKey(ecc.BLS12_381)
	_, err = vk.ReadFrom(&buf)
	if err != nil {
		return nil, nil, err
	}

	return pk, vk, nil
}

func saveCSToFile(cs constraint.ConstraintSystem, csFilePath string) error {
	csFile, err := os.OpenFile(csFilePath, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return nil
	}
	defer func(pkFile *os.File) {
		_ = pkFile.Close()
	}(csFile)

	var buf bytes.Buffer
	_, err = cs.WriteTo(&buf)
	if err != nil {
		return err
	}

	_, err = csFile.Write(buf.Bytes())
	if err != nil {
		return err
	}

	return nil
}

func generateAndSaveKeysToFiles(cs constraint.ConstraintSystem, pkFilePath, vkFilePath string) (groth16.ProvingKey, groth16.VerifyingKey, error) {

	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return nil, nil, err
	}

	pkFile, err := os.OpenFile(pkFilePath, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return nil, nil, err
	}
	defer func(pkFile *os.File) {
		_ = pkFile.Close()
	}(pkFile)

	var buf bytes.Buffer
	_, err = pk.WriteTo(&buf)
	if err != nil {
		return nil, nil, err
	}

	_, err = pkFile.Write(buf.Bytes())
	if err != nil {
		return nil, nil, err

	}

	buf.Reset()

	vkFile, err := os.OpenFile(vkFilePath, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return nil, nil, err
	}
	defer func(vkFile *os.File) {
		_ = vkFile.Close()
	}(vkFile)

	_, err = vk.WriteTo(&buf)
	if err != nil {
		return nil, nil, err
	}

	_, err = vkFile.Write(buf.Bytes())
	if err != nil {
		return nil, nil, err

	}

	return pk, vk, nil
}

func Setup() (*PublicParams, error) {
	if _, errCSFile := os.Stat(CircuitFileName); errCSFile == nil {
		cs, csErr := loadCS(CircuitFileName)
		if csErr != nil {
			return nil, csErr
		}
		return &PublicParams{cs}, nil
	} else {
		cs, csErr := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &Circuit{})
		if csErr != nil {
			return nil, csErr
		}
		errStoreCS := saveCSToFile(cs, CircuitFileName)
		if errStoreCS != nil {
			return nil, errStoreCS
		}
		return &PublicParams{cs}, nil
	}
}

func (pp *PublicParams) KeyGen() (*ProvingKey, *VerifyingKey, error) {
	if _, errVkFile := os.Stat(VkFileName); errVkFile == nil {
		pk, vk, errKGen := loadKeys(PkFileName, VkFileName)
		if errKGen != nil {
			return nil, nil, errKGen
		}
		return &ProvingKey{pk}, &VerifyingKey{vk}, nil
	} else {
		pk, vk, errKeys := generateAndSaveKeysToFiles(pp.CS, PkFileName, VkFileName)
		if errKeys != nil {
			return nil, nil, errKeys
		}
		return &ProvingKey{pk}, &VerifyingKey{vk}, nil
	}
}

func (pp *PublicParams) NewWitness(x, y, sharedInput [MaxInputLength]byte, image [MaxOutputLength]byte) (Witness, error) {
	var sharedPreimageU8 [MaxInputLength]uints.U8
	var xU8 [MaxInputLength]uints.U8
	var yU8 [MaxInputLength]uints.U8
	for i := 0; i < MaxInputLength; i++ {
		sharedPreimageU8[i] = uints.NewU8(sharedInput[i])
		xU8[i] = uints.NewU8(x[i])
		yU8[i] = uints.NewU8(y[i])
	}

	var imageU8 [MaxOutputLength]uints.U8
	for i, d := range image {
		imageU8[i] = uints.NewU8(d)
	}

	assignment := &Circuit{xU8, yU8, sharedPreimageU8, imageU8}
	newWitness, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		return Witness{}, err
	}

	return Witness{assignment, newWitness}, nil
}

func (pp *PublicParams) NewPublicWitness(sharedInput [MaxInputLength]byte, image [MaxOutputLength]byte) (PublicWitness, error) {
	// Just empty witness data to build the circuit
	var xU8 [MaxInputLength]uints.U8
	var yU8 [MaxInputLength]uints.U8

	var sharedInputU8 [MaxInputLength]uints.U8
	for i := 0; i < MaxInputLength; i++ {
		sharedInputU8[i] = uints.NewU8(sharedInput[i])
	}
	var imageU8 [MaxOutputLength]uints.U8
	for i := 0; i < MaxOutputLength; i++ {
		imageU8[i] = uints.NewU8(image[i])
	}
	assignment := &Circuit{xU8, yU8, sharedInputU8, imageU8}
	w, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return PublicWitness{}, err
	}

	return PublicWitness{w}, nil
}

func (pp *PublicParams) Prove(w Witness, pk *ProvingKey) (Proof, error) {
	proof, err := groth16.Prove(pp.CS, pk.key, w.witness)
	if err != nil {
		return Proof{}, err
	}
	return Proof{proof}, nil
}

func (pp *PublicParams) Verify(p Proof, pw PublicWitness, vk *VerifyingKey) bool {
	err := groth16.Verify(p.proof, vk.key, pw.witness)
	if err != nil {
		return false
	}
	return true
}
