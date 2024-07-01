package rsa256

import "testing"

func TestRSA256SignAndVerify(t *testing.T) {
	rsa256 := New(2048)

	message := []byte("Hello, World!")
	signature := rsa256.Sign(message)

	isValid := rsa256.Verify(message, signature)
	if !isValid {
		t.Fatalf("Expacted signature to be valid")
	}
}

func TestRSAWrapperBadSignature(t *testing.T) {
	rsa256 := New(2048)

	message := []byte("Hello, World!")
	signature := rsa256.Sign(message)

	// Modify the sign (simulating a bad sign)
	signature[0] ^= 0xFF

	isValid := rsa256.Verify(message, signature)
	if isValid {
		t.Fatalf("Expected signature verification to fail, but succeeded")
	}
}

func TestRSAWrapperBadMessage(t *testing.T) {
	rsa256 := New(2048)

	message := []byte("Hello, World!")
	signature := rsa256.Sign(message)

	// Modify the message (simulating a different message)
	message[0] ^= 0xFF

	isValid := rsa256.Verify(message, signature)
	if isValid {
		t.Fatalf("Expected sign verification to fail with modified message, but succeeded")
	}
}
