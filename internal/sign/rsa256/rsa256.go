package rsa256

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

// RSA256 holds the RSA keys
type RSA256 struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

// New generates a new RSA256 with the specified key size
func New(keySize int) (*RSA256, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, err
	}
	publicKey := &privateKey.PublicKey

	return &RSA256{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// Sign signs the message with the private key and returns the sign
func (r *RSA256) Sign(message []byte) ([]byte, error) {
	hashed := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, r.PrivateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// Verify verifies the sign with the public key and returns nil if the sign is valid
func (r *RSA256) Verify(message, signature []byte) bool {
	hashed := sha256.Sum256(message)
	return rsa.VerifyPKCS1v15(r.PublicKey, crypto.SHA256, hashed[:], signature) == nil
}
