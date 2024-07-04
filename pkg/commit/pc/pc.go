package pc

import (
	utils "OPPID/pkg/utils"
	GG "github.com/cloudflare/circl/ecc/bls12381"
	"log"
)

const DSTStr = "OPPID_BLS12384_XMD:SHA-256_COM_PC"

// PC holds the parameters for the BLS12-381 curve.
type PC struct {
	G   *GG.G1
	H   *GG.G1
	DST []byte
}

type Commitment struct{ C *GG.G1 }

type Opening struct{ O *GG.Scalar }

// New initializes and returns the curve parameters
func New(dst string) *PC {
	r := utils.GenerateRandomScalar()
	g := GG.G1Generator()
	h := utils.GenerateG1Point(r, g)

	pc := &PC{G: g, H: h, DST: []byte(dst)}
	if dst == "" {
		pc.DST = []byte(DSTStr)
	}

	return pc
}

// Commit computes the Pedersen commit C = mG + oH
func (p *PC) Commit(msg []byte) (*Commitment, *Opening) {
	m := utils.HashToScalar(msg, p.DST)
	o := utils.GenerateRandomScalar()

	g := utils.GenerateG1Point(&m, p.G)
	h := utils.GenerateG1Point(o, p.H)
	c := utils.AddG1Points(g, h)

	if !c.IsOnG1() || o.IsZero() == 1 {
		log.Fatalf("Fatal error: invalid commitment")
	}

	return &Commitment{C: c}, &Opening{O: o}
}

func (p *PC) Open(msg []byte, commitment *Commitment, opening *Opening) bool {
	m := utils.HashToScalar(msg, p.DST)

	g := utils.GenerateG1Point(&m, p.G)
	h := utils.GenerateG1Point(opening.O, p.H)
	c := utils.AddG1Points(g, h)

	return c.IsEqual(commitment.C)
}
