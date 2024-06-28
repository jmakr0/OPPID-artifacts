package oidc

import (
	"OPPID/internal/sign/rsa256"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
)

type OIDC struct {
	RSA  *rsa256.RSA256
	Salt [32]byte
}

type Token struct {
	Sigma []byte
	ppid  []byte
}

func Setup(keySize int) (*OIDC, error) {
	rsa, err := rsa256.New(keySize)
	if err != nil {
		log.Fatalf("Failed to create RSA key pair: %s", err)
	}

	var randomSalt [32]byte
	_, err = rand.Read(randomSalt[:])
	if err != nil {
		return nil, fmt.Errorf("failed to generate random key: %v", err)
	}

	return &OIDC{
		RSA:  rsa,
		Salt: randomSalt,
	}, nil
}

func (o *OIDC) Response(rid []byte, uid []byte, ctx []byte, sid []byte) (*Token, error) {
	// Create a subBuffer to concatenate the input
	var subBuffer bytes.Buffer

	// Write the subject identifier data to buffer
	subBuffer.Write(rid)
	subBuffer.Write(uid)
	subBuffer.Write(o.Salt[:])

	// Get the concatenated byte slice
	subData := subBuffer.Bytes()

	subHash := sha256.New()
	subHash.Write(subData)
	subChecksum := subHash.Sum(nil) // ppid
	//hexSubChecksum := fmt.Sprintf("%x", subChecksum)

	// Create buffer to concatenate token data
	var tkBuffer bytes.Buffer

	// Write token data to buffer
	tkBuffer.Write(rid)
	tkBuffer.Write(subChecksum)
	tkBuffer.Write(ctx)
	tkBuffer.Write(sid)

	tkData := tkBuffer.Bytes()
	sigma, err := o.RSA.Sign(tkData)
	if err != nil {
		log.Fatalf("Failed to sign token: %s", err)
	}

	return &Token{
		Sigma: sigma,
		ppid:  subChecksum,
	}, nil

}

func (o *OIDC) Verify(rid []byte, ppid []byte, ctx []byte, sid []byte, sigma []byte) bool {
	var tkBuffer bytes.Buffer

	tkBuffer.Write(rid)
	tkBuffer.Write(ppid)
	tkBuffer.Write(ctx)
	tkBuffer.Write(sid)

	tkData := tkBuffer.Bytes()

	return o.RSA.Verify(tkData, sigma)
}
