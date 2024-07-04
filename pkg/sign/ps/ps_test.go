package ps

import (
	"OPPID/pkg/utils"
	GG "github.com/cloudflare/circl/ecc/bls12381"
	"testing"
)

func TestNewParams(t *testing.T) {
	ps := Setup(nil)
	_, pk := ps.KeyGen()

	if !pk.X.IsOnG2() || !pk.Y.IsOnG2() {
		t.Fatalf("Generated points are not on G2 curve")
	}
}

func TestSign(t *testing.T) {
	ps := Setup(nil)
	sk, _ := ps.KeyGen()

	msg := []byte("test message")
	sig := ps.Sign(sk, msg)

	if !sig.One.IsOnG1() || !sig.Two.IsOnG1() {
		t.Fatalf("Signature points are not on G1 curve")
	}
}

func TestVerify(t *testing.T) {
	ps := Setup(nil)
	sk, pk := ps.KeyGen()

	msg := []byte("test message")
	sig := ps.Sign(sk, msg)

	isValid := ps.Verify(pk, msg, sig)
	if !isValid {
		t.Fatalf("Failed to verify signature")
	}

	// Test with modified message
	invalidMsg := []byte("modified message")
	isValid = ps.Verify(pk, invalidMsg, sig)
	if isValid {
		t.Fatalf("Invalid signature should not be verified")
	}
}

func TestEmptyMessageSign(t *testing.T) {
	ps := Setup(nil)
	sk, pk := ps.KeyGen()

	msg := []byte("")
	sig := ps.Sign(sk, msg)

	isValid := ps.Verify(pk, msg, sig)
	if !isValid {
		t.Fatalf("Failed to verify signature for empty message")
	}
}

func TestRepeatedSignatures(t *testing.T) {
	ps := Setup(nil)
	sk, pk := ps.KeyGen()

	msg := []byte("test message")
	sig1 := ps.Sign(sk, msg)
	sig2 := ps.Sign(sk, msg)

	if ps.Verify(pk, msg, sig1) && ps.Verify(pk, msg, sig2) {
		if sig1.One.IsEqual(sig2.One) && sig1.Two.IsEqual(sig2.Two) {
			t.Fatalf("Repeated signatures should be unique")
		}
	} else {
		t.Fatalf("Failed to verify repeated signatures")
	}
}

func TestDifferentKeys(t *testing.T) {
	ps := Setup(nil)
	sk1, _ := ps.KeyGen()
	_, pk2 := ps.KeyGen()

	msg := []byte("test message")
	sig := ps.Sign(sk1, msg)

	isValid := ps.Verify(pk2, msg, sig)
	if isValid {
		t.Fatalf("Signature from one key should not verify with a different key")
	}
}

func TestDifferentPublicParams(t *testing.T) {
	ps1 := Setup([]byte("Different DST"))
	ps2 := Setup(nil)
	sk, pk := ps1.KeyGen()

	msg := []byte("test message")
	sig := ps1.Sign(sk, msg)

	isValid := ps2.Verify(pk, msg, sig)
	if isValid {
		t.Fatalf("Signature with different public params should not verify")
	}
}

func TestInvalidSignature(t *testing.T) {
	ps := Setup(nil)
	sk, pk := ps.KeyGen()

	msg := []byte("test message")
	sig := ps.Sign(sk, msg)

	// Tamper with the signature
	sig.One = utils.GenerateG1Point(utils.GenerateRandomScalar(), GG.G1Generator())

	isValid := ps.Verify(pk, msg, sig)
	if isValid {
		t.Fatalf("Invalid signature should not be verified")
	}
}
