package hmac256

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"log"
)

type SecretKey struct {
	key []byte
}

func KeyGen() *SecretKey {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		log.Fatalf("Fatal error creating random HmacPRF key: %v", err)
	}
	return &SecretKey{k}
}

func Eval(k *SecretKey, msg []byte) []byte {
	evl := hmac.New(sha256.New, k.key)
	evl.Write(msg)
	return evl.Sum(nil)
}
