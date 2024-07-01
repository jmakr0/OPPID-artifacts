package rsa256

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"log"
)

type RSA256 struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

func New(keySize int) *RSA256 {
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		log.Fatalf("Fatal error creating RSA key pair: %v", err)
	}

	return &RSA256{PrivateKey: privateKey, PublicKey: &privateKey.PublicKey}
}

// Sign signs the message with the private key and returns the sign
func (r *RSA256) Sign(message []byte) []byte {
	hashed := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, r.PrivateKey, crypto.SHA256, hashed[:])
	if err != nil {
		log.Fatalf("Fatal error creating RSA signature: %v", err)
	}
	return signature
}

// Verify verifies the sign with the public key and returns nil if the sign is valid
func (r *RSA256) Verify(message, signature []byte) bool {
	hashed := sha256.Sum256(message)
	return rsa.VerifyPKCS1v15(r.PublicKey, crypto.SHA256, hashed[:], signature) == nil
}
