package utils

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	GG "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/cloudflare/circl/expander"
	"log"
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

func AddScalars(s1, s2 *GG.Scalar) *GG.Scalar {
	scalar := new(GG.Scalar)
	scalar.Add(s1, s2)
	if scalar.IsZero() != 0 {
		log.Fatalf("Fatal error: invalid scalar after adding scalar")
	}
	return scalar
}

func MulScalars(s1, s2 *GG.Scalar) *GG.Scalar {
	scalar := new(GG.Scalar)
	scalar.Mul(s1, s2)
	if scalar.IsZero() != 0 {
		log.Fatalf("Fatal error: invalid scalar after multiplication")
	}
	return scalar
}

func GenerateRandomScalar() *GG.Scalar {
	scalar := new(GG.Scalar)
	if err := scalar.Random(rand.Reader); err != nil {
		log.Fatalf("Fatal error creating random sclar: %v", err)
	}
	return scalar
}

func GenerateG1Point(scalar *GG.Scalar, base *GG.G1) *GG.G1 {
	point := new(GG.G1)
	point.ScalarMult(scalar, base)
	if !point.IsOnG1() {
		log.Fatalf("Fatal error: invalid G1 point after scalar multiplication")
	}
	return point
}

func AddG1Points(g1 *GG.G1, g2 *GG.G1) *GG.G1 {
	point := new(GG.G1)
	point.Add(g1, g2)
	if !point.IsOnG1() {
		log.Fatalf("Fatal error: invalid G1 point after addition")
	}
	return point
}

func GenerateG2Point(scalar *GG.Scalar, generator *GG.G2) *GG.G2 {
	point := new(GG.G2)
	point.ScalarMult(scalar, generator)
	if !point.IsOnG2() {
		log.Fatalf("Fatal error: invalid G2 point after multiplication")
	}
	return point
}

func AddG2Points(g1 *GG.G2, g2 *GG.G2) *GG.G2 {
	point := new(GG.G2)
	point.Add(g1, g2)
	if !point.IsOnG2() {
		log.Fatalf("Fatal error: invalid G2 point after addition")
	}
	return point
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
