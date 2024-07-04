package hmac256

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"log"
)

type PRF struct {
	K []byte
}

func New() *PRF {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		log.Fatalf("Fatal error creating random HmacPRF key: %v", err)
	}
	return &PRF{K: k}
}

func (prf *PRF) Eval(msg []byte) []byte {
	evl := hmac.New(sha256.New, prf.K)
	evl.Write(msg)
	return evl.Sum(nil)
}
