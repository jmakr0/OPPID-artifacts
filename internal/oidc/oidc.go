// Impl

package oidc

import (
	"OPPID/pkg/sign/rsa256"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"log"
)

type PublicParams struct {
	rsa *rsa256.PublicParams
}

type PublicKey struct {
	key *rsa256.PublicKey
}

type PrivateKey struct {
	key  *rsa256.PrivateKey
	salt *[32]byte
}

type PPID = []byte

type Token struct {
	sig  rsa256.Signature
	ppid PPID
}

func Setup() *PublicParams {
	return &PublicParams{rsa256.Setup(2048)}
}

func (pp *PublicParams) KeyGen() (*PrivateKey, *PublicKey) {
	sk, pk := pp.rsa.KeyGen()

	var salt [32]byte
	_, err := rand.Read(salt[:])
	if err != nil {
		log.Fatalf("failed to generate random salt: %v", err)
	}

	return &PrivateKey{sk, &salt}, &PublicKey{pk}
}

func (pp *PublicParams) Response(k *PrivateKey, rid, uid, ctx, sid []byte) Token {
	var subBuf bytes.Buffer // buffer for subject identifier = ppid
	subBuf.Write(rid)
	subBuf.Write(uid)
	subBuf.Write(k.salt[:])

	subData := subBuf.Bytes()

	subHash := sha256.New()
	subHash.Write(subData)

	var tk Token
	tk.ppid = subHash.Sum(nil) // ppid

	var tkBuf bytes.Buffer
	tkBuf.Write(rid)
	tkBuf.Write(tk.ppid)
	tkBuf.Write(ctx)
	tkBuf.Write(sid)

	tkData := tkBuf.Bytes()
	tk.sig = pp.rsa.Sign(k.key, tkData)

	return tk
}

func (pp *PublicParams) Verify(p *PublicKey, rid, ppid, ctx, sid []byte, tk Token) bool {
	var tkBuffer bytes.Buffer

	tkBuffer.Write(rid)
	tkBuffer.Write(ppid)
	tkBuffer.Write(ctx)
	tkBuffer.Write(sid)

	tkData := tkBuffer.Bytes()

	return pp.rsa.Verify(p.key, tkData, tk.sig)
}
