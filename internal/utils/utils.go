package utils

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"errors"
	GG "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/cloudflare/circl/expander"
	"math/big"
	"strings"
)

// HashToScalar hashes a byte array to a scalar using sha256 hash function
// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-13#name-expand_message_xmd
func HashToScalar(data, dst []byte) GG.Scalar {
	var uniformBytes [64]byte
	xmd := expander.NewExpanderMD(crypto.SHA256, dst)
	copy(uniformBytes[:], xmd.Expand(data, 64))
	var s GG.Scalar
	s.SetBytes(uniformBytes[:]) // internally reduced by curve order
	return s
}

func GenerateRandomScalar() (*GG.Scalar, error) {
	scalar := new(GG.Scalar)
	if err := scalar.Random(rand.Reader); err != nil {
		return nil, err
	}
	return scalar, nil
}

func GenerateG2Point(scalar *GG.Scalar, generator *GG.G2) (*GG.G2, error) {
	point := new(GG.G2)
	point.ScalarMult(scalar, generator)
	if !point.IsOnG2() {
		return nil, errors.New("invalid G2 point")
	}
	return point, nil
}

func ScalarToBytes(scalar *GG.Scalar) ([]byte, error) {
	hexString := scalar.String()
	// Check if the string starts with "0x" and remove it
	if strings.HasPrefix(hexString, "0x") {
		hexString = hexString[2:]
	}

	return hex.DecodeString(hexString)
}

func BytesToScalar(data []byte) *GG.Scalar {
	bigInt := new(big.Int).SetBytes(data)
	scalar := new(GG.Scalar)
	scalar.SetBytes(bigInt.Bytes())
	return scalar
}
