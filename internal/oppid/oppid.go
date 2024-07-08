package oppid

import (
	PC "OPPID/pkg/commit/pc"
	NIZK "OPPID/pkg/nizk/comsig"
	FK "OPPID/pkg/prf/fk"
	PS "OPPID/pkg/sign/ps"
	RSA "OPPID/pkg/sign/rsa256"
	"OPPID/pkg/utils"
	"bytes"
	"errors"
	"fmt"
	GG "github.com/cloudflare/circl/ecc/bls12381"
)

const dstStr = "OPPID_BLS12384_XMD:SHA-256_OPPID_"

type PublicParams struct {
	rsa       *RSA.PublicParams
	dstComSig []byte
	pc        *PC.PublicParams
	ps        *PS.PublicParams
}

type PublicKey struct {
	rsaPk *RSA.PublicKey
	psPk  *PS.PublicKey
}

type PrivateKey struct {
	rsaSk  *RSA.PrivateKey
	psSk   *PS.PrivateKey
	prfKey *FK.Key
}

type Credential struct {
	sig PS.Signature
}

type UsrCommitment struct {
	com PC.Commitment
	bx  *GG.G1
}

type UsrOpening struct {
	opn PC.Opening
	b   *GG.Scalar // blinding
}

type Auth struct {
	proof NIZK.Proof
}

type Token struct {
	sig RSA.Signature
	by  *GG.G1 // blinded evaluation
}

type FinalizedToken struct {
	com     PC.Commitment
	opening PC.Opening
	b       *GG.Scalar
	by      *GG.G1
	sig     RSA.Signature
}

type PairwisePseudonymousIdentifier = []byte

// tokenBytes generates a byte representation of the token
func tokenBytes(com *PC.Commitment, bx, by *GG.G1, ctx, sid []byte) []byte {
	tkBuf := bytes.NewBuffer(nil)
	tkBuf.Write(com.Element.Bytes())
	tkBuf.Write(bx.Bytes()) // blinded rid
	tkBuf.Write(by.Bytes()) // blinded ppid
	tkBuf.Write(ctx)
	tkBuf.Write(sid)
	return tkBuf.Bytes()
}

// hashToPoint hashes input to a point on G1 curve
func hashToPoint(input []byte, dst []byte) *GG.G1 {
	g := new(GG.G1)
	g.Hash(input, dst)
	return g
}

// createAuxBuffer creates an auxiliary buffer for proof inputs
func createAuxBuffer(bx *GG.G1, sid []byte) []byte {
	aux := bytes.NewBuffer(nil)
	aux.Write(bx.Bytes())
	aux.Write(sid)
	return aux.Bytes()
}

// createPublicInputs creates the public inputs for NIZK proof verification
func createPublicInputs(pc *PC.PublicParams, ps *PS.PublicKey, com *PC.Commitment) NIZK.PublicInputs {
	return NIZK.PublicInputs{
		PC:  pc,
		PS:  ps,
		Com: com,
	}
}

func Setup() *PublicParams {
	rsa := RSA.Setup(2048)
	dst := []byte(dstStr + "COM_SIG") // Commitments & signatures must hash to the same domain (dst) for the (NIZK) proof
	pc := PC.Setup(dst)
	ps := PS.Setup(dst)
	return &PublicParams{rsa, dst, pc, ps}
}

func (pp *PublicParams) KeyGen() (*PrivateKey, *PublicKey) {
	rsaSk, rsaPk := pp.rsa.KeyGen()
	psSk, psPk := pp.ps.KeyGen()
	prfKey := FK.KeyGen()
	return &PrivateKey{rsaSk, psSk, prfKey}, &PublicKey{rsaPk, psPk}
}

func (pp *PublicParams) Register(k *PrivateKey, rid []byte) Credential {
	return Credential{sig: pp.ps.Sign(k.psSk, rid)}
}

func (pp *PublicParams) Init(rid []byte) (UsrOpening, UsrCommitment) {
	com, opn := pp.pc.Commit(rid)
	b := utils.GenerateRandomScalar()
	bx := utils.GenerateG1Point(b, hashToPoint(rid, []byte(dstStr)))
	return UsrOpening{opn, b}, UsrCommitment{com, bx}
}

func (pp *PublicParams) Request(ipk *PublicKey, rid []byte, cred Credential, crid UsrCommitment, orid UsrOpening, sid []byte) (Auth, error) {
	bx := utils.GenerateG1Point(orid.b, hashToPoint(rid, []byte(dstStr)))

	if !bx.IsEqual(crid.bx) || !pp.pc.Open(rid, crid.com, orid.opn) {
		return Auth{}, fmt.Errorf("rid blinding or commitment is not correct")
	}

	w := NIZK.Witnesses{
		Msg:     rid,
		Sig:     &cred.sig,
		Opening: &orid.opn,
	}

	p := createPublicInputs(pp.pc, ipk.psPk, &crid.com)
	aux := createAuxBuffer(bx, sid)

	pi := NIZK.New(w, p, aux, pp.dstComSig)
	return Auth{pi}, nil
}

func (pp *PublicParams) Response(isk *PrivateKey, auth Auth, crid UsrCommitment, uid, ctx, sid []byte) (Token, error) {
	p := createPublicInputs(pp.pc, isk.psSk.Pk, &crid.com)
	aux := createAuxBuffer(crid.bx, sid)

	if !NIZK.Verify(auth.proof, p, aux) {
		return Token{}, errors.New("invalid authentication proof")
	}

	by := FK.Eval(isk.prfKey, crid.bx.Bytes(), uid)
	tkBytes := tokenBytes(&crid.com, crid.bx, by, ctx, sid)
	sig := pp.rsa.Sign(isk.rsaSk, tkBytes)

	return Token{sig, by}, nil
}

func (pp *PublicParams) Finalize(ipk *PublicKey, rid, ctx, sid []byte, crid UsrCommitment, orid UsrOpening, t Token) (FinalizedToken, PairwisePseudonymousIdentifier, error) {
	bx := utils.GenerateG1Point(orid.b, hashToPoint(rid, []byte(dstStr)))
	tkBytes := tokenBytes(&crid.com, bx, t.by, ctx, sid)

	if !pp.pc.Open(rid, crid.com, orid.opn) || !pp.rsa.Verify(ipk.rsaPk, tkBytes, t.sig) {
		return FinalizedToken{}, nil, errors.New("commitment or signature did not verify")
	}

	bldInv := new(GG.Scalar)
	bldInv.Inv(orid.b)
	y := utils.GenerateG1Point(bldInv, t.by)

	return FinalizedToken{crid.com, orid.opn, orid.b, t.by, t.sig}, y.Bytes(), nil
}

func (pp *PublicParams) Verify(ipk *PublicKey, rid, ppid, ctx, sid []byte, ft FinalizedToken) bool {
	bx := utils.GenerateG1Point(ft.b, hashToPoint(rid, []byte(dstStr)))
	tkBytes := tokenBytes(&ft.com, bx, ft.by, ctx, sid)

	bldInv := new(GG.Scalar)
	bldInv.Inv(ft.b)
	y := utils.GenerateG1Point(bldInv, ft.by)

	return pp.pc.Open(rid, ft.com, ft.opening) && pp.rsa.Verify(ipk.rsaPk, tkBytes, ft.sig) && bytes.Equal(ppid, y.Bytes())
}
