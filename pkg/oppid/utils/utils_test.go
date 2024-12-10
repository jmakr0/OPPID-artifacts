package utils

import (
	GG "github.com/cloudflare/circl/ecc/bls12381"
	"testing"
)

func TestHashToScalar(t *testing.T) {
	scalar := HashToScalar([]byte("example data"), []byte("example dst"))
	if scalar.IsZero() != 0 {
		t.Errorf("HashToScalar produced an invalid scalar")
	}
}

func TestAddScalars(t *testing.T) {
	s1 := GenerateRandomScalar()
	s2 := GenerateRandomScalar()

	sum, _ := AddScalars(s1, s2)

	if sum.IsZero() != 0 {
		t.Errorf("Expected scalars to be zero")
	}
}

func TestMulScalars(t *testing.T) {
	s1 := GenerateRandomScalar()
	s2 := GenerateRandomScalar()

	product, _ := MulScalars(s1, s2)

	if product.IsZero() != 0 {
		t.Errorf("Expected scalars to be zero")
	}
}

func TestGenerateG1Point(t *testing.T) {
	base := GG.G1Generator()
	scalar := GenerateRandomScalar()

	point := GenerateG1Point(scalar, base)
	if !point.IsOnG1() {
		t.Errorf("GenerateG1Point produced an invalid G1 point")
	}
}

func TestAddG1Points(t *testing.T) {
	g1 := GG.G1Generator()
	g2 := GG.G1Generator()

	sum := AddG1Points(g1, g2)

	if !sum.IsOnG1() {
		t.Errorf("AddG1Points produced an invalid G1 point")
	}
}

func TestGenerateG2Point(t *testing.T) {
	generator := GG.G2Generator()
	scalar := GenerateRandomScalar()

	point := GenerateG2Point(scalar, generator)

	if !point.IsOnG2() {
		t.Errorf("GenerateG2Point produced an invalid G2 point")
	}
}

func TestAddG2Points(t *testing.T) {
	g1 := GG.G2Generator()
	g2 := GG.G2Generator()

	sum := AddG2Points(g1, g2)

	if !sum.IsOnG2() {
		t.Errorf("AddG2Points produced an invalid G2 point")
	}
}

func TestScalarToBytes(t *testing.T) {
	scalar := GenerateRandomScalar()

	bytes := ScalarToBytes(scalar)

	if len(bytes) == 0 {
		t.Errorf("ScalarToBytes produced an empty byte array")
	}
}

func TestBytesToScalar(t *testing.T) {
	scalar := GenerateRandomScalar()
	bytes := ScalarToBytes(scalar)

	reconstructedScalar := BytesToScalar(bytes)

	if reconstructedScalar.IsEqual(scalar) != 1 {
		t.Errorf("BytesToScalar did not reconstruct the scalar correctly")
	}
}

func TestAddScalarsErrorOnZero(t *testing.T) {
	one := new(GG.Scalar)
	one.SetOne()
	minusOne := new(GG.Scalar)
	minusOne.SetOne()
	minusOne.Neg()

	_, err := AddScalars(one, minusOne)
	if err == nil {
		t.Errorf("Expected error when adding one and zero, but got nil")
	} else {
		t.Logf("Received expected error: %v", err)
	}
}

func TestAddScalarsErrorOnOne(t *testing.T) {
	zero := new(GG.Scalar)
	one := new(GG.Scalar)
	one.SetOne()

	_, err := AddScalars(one, zero)
	if err == nil {
		t.Errorf("Expected error when adding one and zero, but got nil")
	} else {
		t.Logf("Received expected error: %v", err)
	}
}

func TestMulScalarsErrorOnZero(t *testing.T) {
	zero := new(GG.Scalar) // Will be "zeroed" initialized
	if zero.IsZero() != 1 {
		t.Errorf("Zero scalar is not zero")
	}
	rndScalar := GenerateRandomScalar()

	_, err := MulScalars(rndScalar, zero)
	if err == nil {
		t.Errorf("Expected error when adding one and zero, but got nil")
	} else {
		t.Logf("Received expected error: %v", err)
	}
}
