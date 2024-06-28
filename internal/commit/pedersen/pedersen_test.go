package pedersen

import (
	"crypto/rand"
	GG "github.com/cloudflare/circl/ecc/bls12381"
	"testing"
)

func TestNew(t *testing.T) {
	params, _ := New()
	if !params.G.IsOnG1() {
		t.Fatalf("G should be on G1")
	}
	if !params.H.IsOnG1() {
		t.Fatalf("H should be on G1")
	}
}

func TestCommitValidMessage(t *testing.T) {
	pc, _ := New()
	msg := []byte("test message")

	commitment, opening, err := pc.Commit(msg)
	if err != nil {
		t.Fatalf("Failed to run commitment: %s", err)
	}
	if !commitment.IsOnG1() {
		t.Fatalf("Commitment should be on G1")
	}
	if opening.IsZero() == 1 {
		t.Fatalf("Random scalar o should be valid")
	}
}

func TestOpenWithCorrectParameters(t *testing.T) {
	pc, _ := New()
	msg := []byte("test message")

	commitment, opening, _ := pc.Commit(msg)
	isValid := pc.Open(msg, &commitment, &opening)
	if !isValid {
		t.Fatalf("Open should validate the correct commitment")
	}
}

func TestOpenWithIncorrectMessage(t *testing.T) {
	pc, _ := New()
	msg := []byte("test message")

	commitment, opening, _ := pc.Commit(msg)

	invalidMsg := []byte("wrong message")
	isValid := pc.Open(invalidMsg, &commitment, &opening)
	if isValid {
		t.Fatalf("Open should not validate the incorrect commitment")
	}
}

func TestOpenWithIncorrectRandomness(t *testing.T) {
	pc, _ := New()

	msg := []byte("test message")
	commitment, _, _ := pc.Commit(msg)

	invalidRandomOpening := new(GG.Scalar)
	_ = invalidRandomOpening.Random(rand.Reader)
	invalidZeroOpening := new(GG.Scalar)

	isValid1 := pc.Open(msg, &commitment, invalidRandomOpening)
	isValid2 := pc.Open(msg, &commitment, invalidZeroOpening)
	if isValid1 || isValid2 {
		t.Fatalf("Open should not validate the incorrect commitment with wrong randomness")
	}
}
