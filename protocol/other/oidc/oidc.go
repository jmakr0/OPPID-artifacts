// Implements the core cryptographic operations of the standard OIDC protocol with Pairwise Pseudonymous
// Identifier (PPID) [1] in our setting.

// References:
// [1] https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg

package oidc

import (
	RSA "OPPID-artifacts/pkg/oppid/sign/rsa256"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"log"
)

type PublicParams struct {
	rsa *RSA.PublicParams
}

type PublicKey struct {
	key *RSA.PublicKey
}

type PrivateKey struct {
	key  *RSA.PrivateKey
	salt [32]byte
}

type PPID = [32]byte

type Token struct {
	sig  RSA.Signature
	ppid PPID
}

func tokenBytes(rid []byte, ppid PPID, ctx, sid []byte) []byte {
	var buf bytes.Buffer
	buf.Write(rid)
	buf.Write(ppid[:])
	buf.Write(ctx)
	buf.Write(sid)
	return buf.Bytes()
}

func Setup() *PublicParams {
	return &PublicParams{RSA.Setup(2048)}
}

func (pp *PublicParams) KeyGen() (*PrivateKey, *PublicKey) {
	sk, pk := pp.rsa.KeyGen()

	var salt [32]byte
	_, err := rand.Read(salt[:])
	if err != nil {
		log.Fatalf("failed to generate random salt: %v", err)
	}

	return &PrivateKey{sk, salt}, &PublicKey{pk}
}

func (pp *PublicParams) Response(k *PrivateKey, rid, uid, ctx, sid []byte) Token {
	var tk Token

	var buf bytes.Buffer
	buf.Write(rid)
	buf.Write(uid)
	buf.Write(k.salt[:])

	tk.ppid = sha256.Sum256(buf.Bytes())
	tkBytes := tokenBytes(rid, tk.ppid, ctx, sid)
	tk.sig = pp.rsa.Sign(k.key, tkBytes)

	return tk
}

func (pp *PublicParams) Verify(p *PublicKey, rid, ctx, sid []byte, tk Token) bool {
	tkBytes := tokenBytes(rid, tk.ppid, ctx, sid)
	return pp.rsa.Verify(p.key, tkBytes, tk.sig)
}
