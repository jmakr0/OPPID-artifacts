package rsa256

import "testing"

func TestRSA256SignAndVerify(t *testing.T) {
	rsa := Setup(2048)
	sk, pk := rsa.KeyGen()

	msg := []byte("Hello, World!")
	sig := rsa.Sign(sk, msg)

	isValid := rsa.Verify(pk, msg, sig)
	if !isValid {
		t.Fatalf("Expacted signature to be valid")
	}
}

func TestRSAWrapperBadSignature(t *testing.T) {
	rsa := Setup(2048)
	sk, pk := rsa.KeyGen()

	msg := []byte("Hello, World!")
	sig := rsa.Sign(sk, msg)

	// Modify signature (simulating a bad sign)
	sig[0] ^= 0xFF

	isValid := rsa.Verify(pk, msg, sig)
	if isValid {
		t.Fatalf("Expected signature verification to fail, but succeeded")
	}
}

func TestRSAWrapperBadMessage(t *testing.T) {
	rsa := Setup(2048)
	sk, pk := rsa.KeyGen()

	msg := []byte("Hello, World!")
	sig := rsa.Sign(sk, msg)

	// Modify message (simulating a different message)
	msg[0] ^= 0xFF

	isValid := rsa.Verify(pk, msg, sig)
	if isValid {
		t.Fatalf("Expected sign verification to fail with modified message, but succeeded")
	}
}
