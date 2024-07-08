package hmac256

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"log"
)

type Key = []byte

func KeyGen() *Key {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		log.Fatalf("Fatal error creating random hmacPRF key: %v", err)
	}
	return &k
}

func Eval(k *Key, msg []byte) []byte {
	y := hmac.New(sha256.New, *k)
	y.Write(msg)
	return y.Sum(nil)
}
