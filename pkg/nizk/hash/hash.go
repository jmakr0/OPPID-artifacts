package hash

import (
	"bytes"
	"crypto/sha256"
	"fmt"
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
	circuitFileName = "circuit.r1cs.bin"
	pkFileName      = "proving_key.bin"
	vkFileName      = "verification_key.bin"
)

type PublicParams struct{ cs constraint.ConstraintSystem }

type ProvingKey struct{ key groth16.ProvingKey }
type VerifyingKey struct{ key groth16.VerifyingKey }

type Witness struct {
	assignment *Circuit // makes testing easier
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
	if _, errCSFile := os.Stat(circuitFileName); errCSFile == nil {
		cs, csErr := loadCS(circuitFileName)
		if csErr != nil {
			return nil, csErr
		}
		return &PublicParams{cs}, nil
	} else {
		cs, csErr := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &Circuit{})
		if csErr != nil {
			return nil, csErr
		}
		errStoreCS := saveCSToFile(cs, circuitFileName)
		if errStoreCS != nil {
			return nil, errStoreCS
		}
		return &PublicParams{cs}, nil
	}
}

func (pp *PublicParams) KeyGen() (*ProvingKey, *VerifyingKey, error) {
	if _, errVkFile := os.Stat(vkFileName); errVkFile == nil {
		pk, vk, errKGen := loadKeys(pkFileName, vkFileName)
		if errKGen != nil {
			return nil, nil, errKGen
		}
		return &ProvingKey{pk}, &VerifyingKey{vk}, nil
	} else {
		pk, vk, errKeys := generateAndSaveKeysToFiles(pp.cs, pkFileName, vkFileName)
		if errKeys != nil {
			return nil, nil, errKeys
		}
		return &ProvingKey{pk}, &VerifyingKey{vk}, nil
	}
}

// NewWitness returns a witness for image = H( H(pub || x) || y) with H = sha256, where pub is public and x,y stay secret
func (pp *PublicParams) NewWitness(x, y, pub []byte) (*Witness, error) {
	if len(x) > MaxInputLength || len(y) > MaxInputLength || len(pub) > MaxInputLength {
		return nil, fmt.Errorf("invalid input length, expects at most %d", MaxInputLength)
	}

	// Copy input to arrays with max length
	var inPubBytes [MaxInputLength]byte
	copy(inPubBytes[:], pub)

	var inXBytes [MaxInputLength]byte
	copy(inXBytes[:], x)

	var inYBytes [MaxInputLength]byte
	copy(inYBytes[:], y)

	// Create hashes
	innerPreimage := append(inPubBytes[:], inXBytes[:]...)
	innerHash := sha256.Sum256(innerPreimage)

	preimage := append(innerHash[:], inYBytes[:]...)
	hash := sha256.Sum256(preimage)

	// Transfer to correct format for circuit
	var preimagePubU8 [MaxInputLength]uints.U8
	var xU8 [MaxInputLength]uints.U8
	var yU8 [MaxInputLength]uints.U8
	for i := 0; i < MaxInputLength; i++ {
		preimagePubU8[i] = uints.NewU8(inPubBytes[i])
		xU8[i] = uints.NewU8(inXBytes[i])
		yU8[i] = uints.NewU8(inYBytes[i])
	}

	var imageU8 [OutputLength]uints.U8
	for i, d := range hash {
		imageU8[i] = uints.NewU8(d)
	}

	assignment := &Circuit{xU8, yU8, preimagePubU8, imageU8}
	w, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		return nil, err
	}

	return &Witness{assignment, w}, nil
}

func (pp *PublicParams) Prove(w *Witness, pk *ProvingKey) (Proof, PublicWitness, error) {
	proof, err := groth16.Prove(pp.cs, pk.key, w.witness)
	if err != nil {
		return Proof{}, PublicWitness{}, err
	}
	pubWitness, err := w.witness.Public()
	if err != nil {
		return Proof{}, PublicWitness{}, err
	}

	return Proof{proof}, PublicWitness{pubWitness}, nil
}

func (pp *PublicParams) Verify(p Proof, pw PublicWitness, vk *VerifyingKey) bool {
	err := groth16.Verify(p.proof, vk.key, pw.witness)
	if err != nil {
		return false
	}
	return true
}
