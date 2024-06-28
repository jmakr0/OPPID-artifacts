package hmac256

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
)

type PRF struct {
	K []byte
}

func New() (*PRF, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return &PRF{K: k}, nil
}

func (prf *PRF) Eval(msg []byte) []byte {
	evl := hmac.New(sha256.New, prf.K)
	evl.Write(msg)
	return evl.Sum(nil)
}
