// Package implements basic Pedersen commitments [1].
// [1] https://link.springer.com/chapter/10.1007/3-540-46766-1_9

package pc

import (
	"OPPID/pkg/utils"
	GG "github.com/cloudflare/circl/ecc/bls12381"
	"log"
)

const dstStr = "OPPID_BLS12384_XMD:SHA-256_COM_PC_"

type PublicParams struct {
	G   *GG.G1
	H   *GG.G1
	Dst []byte
}

type Commitment struct{ Element *GG.G1 }
type Opening struct{ Scalar *GG.Scalar }

func Setup(dst []byte) *PublicParams {
	r := utils.GenerateRandomScalar()
	g := GG.G1Generator()
	h := utils.GenerateG1Point(r, g)

	if dst == nil {
		return &PublicParams{g, h, []byte(dstStr)}
	}
	return &PublicParams{g, h, dst}
}

func (p *PublicParams) Commit(msg []byte) (Commitment, Opening) {
	m := utils.HashToScalar(msg, p.Dst)
	g := utils.GenerateG1Point(&m, p.G)

	var o Opening
	o.Scalar = utils.GenerateRandomScalar()
	h := utils.GenerateG1Point(o.Scalar, p.H)

	var c Commitment
	c.Element = utils.AddG1Points(g, h)

	if !c.Element.IsOnG1() || o.Scalar.IsZero() == 1 {
		log.Fatalf("Fatal error: invalid commitment")
	}

	return c, o
}

func (p *PublicParams) Open(msg []byte, c Commitment, o Opening) bool {
	m := utils.HashToScalar(msg, p.Dst)
	g := utils.GenerateG1Point(&m, p.G)
	h := utils.GenerateG1Point(o.Scalar, p.H)
	c1 := utils.AddG1Points(g, h)

	return c1.IsEqual(c.Element)
}
