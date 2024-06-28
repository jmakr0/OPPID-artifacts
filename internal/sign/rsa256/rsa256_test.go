package rsa256

import "testing"

func TestRSA256_SignAndVerify(t *testing.T) {
	// Create a new RSAWrapper with a 2048-bit key
	rsa256, err := New(2048)
	if err != nil {
		t.Fatalf("Failed to create RSA wrapper: %s", err)
	}

	message := []byte("Hello, World!")

	signature, err := rsa256.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %s", err)
	}

	isValid := rsa256.Verify(message, signature)
	if !isValid {
		t.Fatalf("Failed to verify sign: %s", err)
	}
}

func TestRSAWrapper_BadSignature(t *testing.T) {
	// Create a new RSAWrapper with a 2048-bit key
	rsa256, err := New(2048)
	if err != nil {
		t.Fatalf("Failed to create RSA wrapper: %s", err)
	}

	message := []byte("Hello, World!")

	signature, err := rsa256.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %s", err)
	}

	// Modify the sign (simulating a bad sign)
	signature[0] ^= 0xFF

	// Verify the modified sign (should fail)
	isValid := rsa256.Verify(message, signature)
	if isValid {
		t.Fatalf("Expected sign verification to fail, but succeeded")
	}
}

func TestRSAWrapper_BadMessage(t *testing.T) {
	// Create a new RSAWrapper with a 2048-bit key
	rsa256, err := New(2048)
	if err != nil {
		t.Fatalf("Failed to create RSA wrapper: %s", err)
	}

	message := []byte("Hello, World!")

	signature, err := rsa256.Sign(message)
	if err != nil {
		t.Fatalf("Failed to sign message: %s", err)
	}

	// Modify the message (simulating a different message)
	message[0] ^= 0xFF

	// Verify the sign with the modified message (should fail)
	isValid := rsa256.Verify(message, signature)
	if isValid {
		t.Fatalf("Expected sign verification to fail with modified message, but succeeded")
	}
}
