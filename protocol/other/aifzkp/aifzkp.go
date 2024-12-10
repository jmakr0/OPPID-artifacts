// Implements the core cryptographic operations of the AIF-ZKP scheme from [1]. For simplicity, there is no member state
// that tracks RPs that have been already registered.

// References:
// [1] https://petsymposium.org/popets/2023/popets-2023-0100.php

package aifzkp

import (
	PC "OPPID/pkg/oppid/commit/pc"
	PS "OPPID/pkg/oppid/sign/ps"
	RSA "OPPID/pkg/oppid/sign/rsa256"
	NIZK "OPPID/pkg/other/nizk/comsig"
	"bytes"
	"errors"
	"log"
)

const dstStr = "OPPID_BLS12384_XMD:SHA-256_AIF-ZKP_"

type PublicParams struct {
	rsa *RSA.PublicParams
	dst []byte
	pc  *PC.PublicParams
	ps  *PS.PublicParams
}

type PublicKey struct {
	rsaPk *RSA.PublicKey
	psPk  *PS.PublicKey
}

type PrivateKey struct {
	rsaSk *RSA.PrivateKey
	psSk  *PS.PrivateKey
}

type Credential struct {
	sig PS.Signature
}

type UsrCommitment struct {
	com PC.Commitment
}

type UsrOpening struct {
	opening PC.Opening
}

type Auth struct {
	proof NIZK.Proof
}

type Token struct {
	sig RSA.Signature
}

type FinalizedToken struct {
	com     PC.Commitment
	opening PC.Opening
	sig     RSA.Signature
}

func tokenBytes(com *PC.Commitment, uid, ctx, sid []byte) []byte {
	var buf bytes.Buffer
	buf.Write([]byte(dstStr + "TOKEN"))
	buf.Write(com.Element.Bytes())
	buf.Write(uid)
	buf.Write(ctx)
	buf.Write(sid)
	return buf.Bytes()
}

func Setup() *PublicParams {
	rsa := RSA.Setup(2048)

	dst := []byte(dstStr + "COM_SIG") // Commitments & signatures hash to the same domain (dst) for the (NIZK) proof
	pc := PC.Setup(dst)
	ps := PS.Setup(dst)

	return &PublicParams{rsa, dst, pc, ps}
}

func (pp *PublicParams) KeyGen() (*PrivateKey, *PublicKey) {
	rsaSk, rsaPk := pp.rsa.KeyGen()
	psSk, psPk := pp.ps.KeyGen()
	return &PrivateKey{rsaSk, psSk}, &PublicKey{rsaPk, psPk}
}

func (pp *PublicParams) Register(k *PrivateKey, rid []byte) Credential {
	return Credential{pp.ps.Sign(k.psSk, rid)}
}

func (pp *PublicParams) Init(rid []byte) (UsrOpening, UsrCommitment) {
	com, opn := pp.pc.Commit(rid)
	return UsrOpening{opn}, UsrCommitment{com}
}

func (pp *PublicParams) Request(ipk *PublicKey, rid []byte, c Credential, crid UsrCommitment, orid UsrOpening, sid []byte) Auth {
	if !pp.pc.Open(rid, crid.com, orid.opening) {
		log.Fatalf("Commitment is not correct")
	}

	var w NIZK.Witnesses
	w.Msg = rid
	w.Sig = &c.sig
	w.Opening = &orid.opening

	var p NIZK.PublicInputs
	p.PC = pp.pc
	p.PS = ipk.psPk
	p.Com = &crid.com

	pi := NIZK.Prove(w, p, sid, pp.dst)

	return Auth{pi}
}

func (pp *PublicParams) Response(isk *PrivateKey, auth Auth, crid UsrCommitment, uid, ctx, sid []byte) (Token, error) {
	var p NIZK.PublicInputs
	p.PC = pp.pc
	p.PS = isk.psSk.Pk
	p.Com = &crid.com

	isValid := NIZK.Verify(auth.proof, p, sid[:])
	if !isValid {
		return Token{}, errors.New("invalid authentication proof")
	}

	tkBytes := tokenBytes(&crid.com, uid, ctx, sid)

	var tk Token
	tk.sig = pp.rsa.Sign(isk.rsaSk, tkBytes)

	return tk, nil
}

func (pp *PublicParams) Finalize(ipk *PublicKey, rid, uid, ctx, sid []byte, crid UsrCommitment, orid UsrOpening, t Token) (FinalizedToken, error) {
	tkBytes := tokenBytes(&crid.com, uid, ctx, sid)
	isValidCom := pp.pc.Open(rid, crid.com, orid.opening)
	isValidSig := pp.rsa.Verify(ipk.rsaPk, tkBytes, t.sig)
	if !isValidCom || !isValidSig {
		return FinalizedToken{}, errors.New("commitment or signature did not verify")
	}

	return FinalizedToken{crid.com, orid.opening, t.sig}, nil
}

func (pp *PublicParams) Verify(ipk *PublicKey, rid, uid, ctx, sid []byte, ft FinalizedToken) bool {
	tkBytes := tokenBytes(&ft.com, uid, ctx, sid)

	isValidCom := pp.pc.Open(rid, ft.com, ft.opening)
	isValidSig := pp.rsa.Verify(ipk.rsaPk, tkBytes, ft.sig)

	return isValidCom && isValidSig
}
