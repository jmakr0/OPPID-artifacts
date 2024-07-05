// simplifications: does not consider member state

package aifzkp

import (
	PC "OPPID/pkg/commit/pc"
	NIZK "OPPID/pkg/nizk/comsig"
	PS "OPPID/pkg/sign/ps"
	"OPPID/pkg/sign/rsa256"
	"log"
)

const dstStr = "OPPID_BLS12384_XMD:SHA-256_AIF-ZKP_"

type PublicParams struct {
	rsa       *rsa256.PublicParams
	dstComSig []byte
	pc        *PC.PublicParams
	ps        *PS.PublicParams
}

type PublicKey struct {
	rsaPk *rsa256.PublicKey
	psPk  *PS.PublicKey
}

type PrivateKey struct {
	rsaSk *rsa256.PrivateKey
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

func Setup() *PublicParams {
	rsa := rsa256.Setup(2048)

	dst := []byte(dstStr + "COM_SIG") // Commitments & signatures must hash to the same domain (dst) for the (NIZK) proof
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
	var cred Credential
	cred.sig = pp.ps.Sign(k.psSk, rid)
	return cred
}

func (pp *PublicParams) Init(rid []byte) (*UsrOpening, *UsrCommitment) {
	com, opn := pp.pc.Commit(rid)
	return &UsrOpening{opn}, &UsrCommitment{com}
}

func (pp *PublicParams) Request(ipk *PublicKey, rid []byte, c *Credential, crid UsrCommitment, orid UsrOpening, sid []byte) Auth {
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

	pi := NIZK.New(w, p, sid, pp.dstComSig)

	return Auth{pi}
}

func (pp *PublicParams) Response() {}

func (pp *PublicParams) Finalize() {}

func (pp *PublicParams) Verify() bool {
	return true
}
