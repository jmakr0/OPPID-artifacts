package pc

import (
	"OPPID/pkg/oppid/utils"
	GG "github.com/cloudflare/circl/ecc/bls12381"
	"testing"
)

func TestNew(t *testing.T) {
	pc := Setup(nil)
	if !pc.G.IsOnG1() {
		t.Fatalf("G should be on G1")
	}
	if !pc.H.IsOnG1() {
		t.Fatalf("H should be on G1")
	}
}

func TestCommitValidMessage(t *testing.T) {
	pc := Setup(nil)
	msg := []byte("test message")

	commitment, opening := pc.Commit(msg)
	if !commitment.Element.IsOnG1() {
		t.Fatalf("Commitment should be on G1")
	}
	if opening.Scalar.IsZero() == 1 {
		t.Fatalf("Opening should be valid")
	}
}

func TestOpenWithCorrectParameters(t *testing.T) {
	pc := Setup(nil)
	msg := []byte("test message")

	commitment, opening := pc.Commit(msg)
	isValid := pc.Open(msg, commitment, opening)
	if !isValid {
		t.Fatalf("Open should validate the correct commitment")
	}
}

func TestOpenWithIncorrectMessage(t *testing.T) {
	pc := Setup(nil)
	msg := []byte("test message")

	commitment, opening := pc.Commit(msg)

	invalidMsg := []byte("wrong message")
	isValid := pc.Open(invalidMsg, commitment, opening)
	if isValid {
		t.Fatalf("Open should not validate the incorrect commitment")
	}
}

func TestOpenWithIncorrectRandomness(t *testing.T) {
	pc := Setup([]byte("Test dst"))

	msg := []byte("test message")
	commitment, _ := pc.Commit(msg)

	r := utils.GenerateRandomScalar()

	invalidRandomOpening := new(Opening)
	invalidRandomOpening.Scalar = r

	invalidZeroOpening := &Opening{Scalar: new(GG.Scalar)}

	isValid1 := pc.Open(msg, commitment, *invalidRandomOpening)
	isValid2 := pc.Open(msg, commitment, *invalidZeroOpening)
	if isValid1 || isValid2 {
		t.Fatalf("Open should not validate the incorrect commitment with wrong randomness")
	}
}
