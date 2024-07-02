// simplifications: does not consider member state

package aifzkp

import (
	PC "OPPID/internal/commit/pc"
	NIZK "OPPID/internal/nizk/commitsig"
	PS "OPPID/internal/sign/ps"
	"OPPID/internal/sign/rsa256"
	"OPPID/internal/utils"
	GG "github.com/cloudflare/circl/ecc/bls12381"
	"log"
)

const DSTStr = "abc"

type AIF struct {
	rsa *rsa256.RSA256
	ps  *PS.PS
	pc  *PC.PC
	dst []byte
}

type Credential struct {
	value *PS.Signature
}

type UsrCommitment struct {
	com    *PC.Commitment
	bldRid *GG.G1
}

type UsrOpening struct {
	opening *PC.Opening
	bld     *GG.Scalar
}

func New() *AIF {
	rsa := rsa256.New(2048)
	ps := PS.New(DSTStr + "_COM_SIG")
	pc := PC.New(DSTStr + "_COM_SIG")

	return &AIF{rsa: rsa, ps: ps, pc: pc, dst: []byte(DSTStr)}
}

// Reg issues PS signature as creadential; does not keep member state for simplicity
func (pp *AIF) Reg(rid []byte) *Credential {
	return &Credential{value: pp.ps.Sign(rid)}
}

func (pp *AIF) Init(rid []byte) (*UsrCommitment, *UsrOpening) {
	com, opn := pp.pc.Commit(rid)

	g := new(GG.G1)
	g.Hash(rid, pp.dst)

	r := utils.GenerateRandomScalar()
	bldRid := utils.GenerateG1Point(r, g)

	return &UsrCommitment{com, bldRid}, &UsrOpening{opn, r}
}

func (pp *AIF) Request(rid []byte, cred *Credential, crid *UsrCommitment, orid *UsrOpening, sid []byte) *NIZK.Proof {
	g := new(GG.G1)
	g.Hash(rid, pp.dst)

	bldRid := utils.GenerateG1Point(orid.bld, g)
	if !bldRid.IsEqual(crid.bldRid) || !pp.pc.Open(rid, crid.com, orid.opening) {
		log.Fatalf("Commitment or blinding do not verify")
	}

	w := &NIZK.Witnesses{
		Msg:     rid,
		Sig:     cred.value,
		Opening: orid.opening,
	}
	pub := &NIZK.PublicInputs{
		PSParams: pp.ps,
		PCParams: pp.pc,
		Com:      crid.com,
	}

	return NIZK.New(w, pub, sid)
}

func (pp *AIF) Response() {}
func (pp *AIF) Finalize() {}
func (pp *AIF) Verify() bool {
	return true
}
