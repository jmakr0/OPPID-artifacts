package oidc

import (
	"OPPID/internal/sign/rsa256"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"log"
)

type OIDC struct {
	rsa  *rsa256.RSA256
	salt [32]byte
}

type Token struct {
	Sigma []byte
	ppid  []byte
}

func New(keySize int) *OIDC {
	rsa := rsa256.New(keySize)
	var salt [32]byte

	_, err := rand.Read(salt[:])
	if err != nil {
		log.Fatalf("Failed to generate random salt: %v", err)
	}

	return &OIDC{rsa: rsa, salt: salt}
}

func (o *OIDC) Response(rid []byte, uid []byte, ctx []byte, sid []byte) *Token {
	var subBuf bytes.Buffer

	// Write the subject identifier tkBuf to buffer
	subBuf.Write(rid)
	subBuf.Write(uid)
	subBuf.Write(o.salt[:])

	// Get the concatenated byte slice
	subData := subBuf.Bytes()

	subHash := sha256.New()
	subHash.Write(subData)
	subChecksum := subHash.Sum(nil) // ppid

	// Create buffer to concatenate token tkBuf
	var tkBuf bytes.Buffer

	// Write token tkBuf to buffer
	tkBuf.Write(rid)
	tkBuf.Write(subChecksum)
	tkBuf.Write(ctx)
	tkBuf.Write(sid)

	tkData := tkBuf.Bytes()
	sigma := o.rsa.Sign(tkData)

	return &Token{Sigma: sigma, ppid: subChecksum}
}

func (o *OIDC) Verify(rid []byte, ppid []byte, ctx []byte, sid []byte, sigma []byte) bool {
	var tkBuffer bytes.Buffer

	tkBuffer.Write(rid)
	tkBuffer.Write(ppid)
	tkBuffer.Write(ctx)
	tkBuffer.Write(sid)

	tkData := tkBuffer.Bytes()

	return o.rsa.Verify(tkData, sigma)
}
