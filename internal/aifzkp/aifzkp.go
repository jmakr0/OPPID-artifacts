// simplifications: does not consider member state

package aifzkp

import (
	PC "OPPID/pkg/commit/pc"
	NIZK "OPPID/pkg/nizk/commitsig"
	PS "OPPID/pkg/sign/ps"
	"OPPID/pkg/sign/rsa256"
	"OPPID/pkg/utils"
	GG "github.com/cloudflare/circl/ecc/bls12381"
	"log"
)

const DSTStr = "abc"

type AIF struct {
	rsa *rsa256.RSA256
	ps  *PS.PublicParams
	pc  *PC.PublicParams
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

type Auth struct {
	proof *NIZK.Proof
}

func New() *AIF {
	rsa := rsa256.KeyGen(2048)
	ps := PS.KeyGen(DSTStr + "_COM_SIG")
	pc := PC.Setup(DSTStr + "_COM_SIG")

	return &AIF{rsa: rsa, ps: ps, pc: pc, dst: []byte(DSTStr)}
}

// Reg issues PublicParams signature as creadential; does not keep member state for simplicity
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

func (pp *AIF) Request(rid []byte, cred *Credential, crid *UsrCommitment, orid *UsrOpening, sid []byte) *Auth {
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
	pi := NIZK.New(w, pub, sid)

	return &Auth{pi}
}

func (pp *AIF) Response() {}
func (pp *AIF) Finalize() {}
func (pp *AIF) Verify() bool {
	return true
}
