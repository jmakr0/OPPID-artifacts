package rsa256

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"log"
)

type PublicParams struct{ keySize int }

type PublicKey struct{ key *rsa.PublicKey }
type PrivateKey struct{ key *rsa.PrivateKey }

type Signature = []byte

func Setup(keySize int) *PublicParams {
	return &PublicParams{keySize}
}

func (pp *PublicParams) KeyGen() (*PrivateKey, *PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, pp.keySize)
	if err != nil {
		log.Fatalf("Fatal error creating rsa key pair: %v", err)
	}
	return &PrivateKey{key: privateKey}, &PublicKey{key: &privateKey.PublicKey}
}

func (pp *PublicParams) Sign(k *PrivateKey, message []byte) Signature {
	hashed := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, k.key, crypto.SHA256, hashed[:])
	if err != nil {
		log.Fatalf("Fatal error creating rsa signature: %v", err)
	}
	return signature
}

func (pp *PublicParams) Verify(p *PublicKey, message, signature []byte) bool {
	hashed := sha256.Sum256(message)
	return rsa.VerifyPKCS1v15(p.key, crypto.SHA256, hashed[:], signature) == nil
}
