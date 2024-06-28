package ps

import (
	GG "github.com/cloudflare/circl/ecc/bls12381"
	"testing"
)

func TestNewParams(t *testing.T) {
	params, err := New()
	if err != nil {
		t.Fatalf("Failed to initialize parameters: %v", err)
	}
	if !params.X.IsOnG2() || !params.Y.IsOnG2() {
		t.Fatalf("Generated points are not on G2 curve")
	}
}

func TestSign(t *testing.T) {
	ps, _ := New()

	msg := []byte("test message")
	sig, err := ps.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}
	if !sig.Sig1.IsOnG1() || !sig.Sig2.IsOnG1() {
		t.Fatalf("Signature points are not on G1 curve")
	}
}

func TestVerify(t *testing.T) {
	ps, _ := New()

	msg := []byte("test message")
	sig, err := ps.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	isValid, err := ps.Verify(msg, *sig)
	if err != nil || !isValid {
		t.Fatalf("Failed to verify isValid signature: %v", err)
	}

	// Test with modified message
	invalidMsg := []byte("modified message")
	isValid, err = ps.Verify(invalidMsg, *sig)
	if err == nil && isValid {
		t.Fatalf("Invalid signature should not be verified")
	}
}

func TestVerifyEdgeCases(t *testing.T) {
	ps, _ := New()

	msg := []byte("test message")
	sig, err := ps.Sign(msg)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	// Test with identity point
	identitySig := Signature{
		Sig1: new(GG.G1),
		Sig2: sig.Sig2,
	}
	identitySig.Sig1.IsIdentity()
	valid, err := ps.Verify(msg, identitySig)
	if err == nil && valid {
		t.Fatalf("Signature with identity point should not be verified")
	}

	// Test with non-G1 point (using point from G2 as invalid point for G1)
	invalidSig := Signature{
		Sig1: new(GG.G1), // not properly initialized, hence not on G1
		Sig2: sig.Sig2,
	}
	valid, err = ps.Verify(msg, invalidSig)
	if err == nil && valid {
		t.Fatalf("Signature with invalid G1 point should not be verified")
	}
}
