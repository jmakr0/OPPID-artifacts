package pedersen

import (
	utils "OPPID/internal/utils"
	"crypto/rand"
	"fmt"
	GG "github.com/cloudflare/circl/ecc/bls12381"
)

const DST = "OPPID_BLS12384_XMD:SHA-256_COM_PC"

// Params holds the parameters for the BLS12-381 curve.
type Params struct {
	G *GG.G1
	H *GG.G1
}

type Commitment struct {
	C *GG.G1
}

type Opening struct {
	O *GG.Scalar
}

// New initializes and returns the curve parameters.
func New() (*Params, error) {
	// Define base points g and h on the curve
	g := GG.G1Generator()

	r := new(GG.Scalar)
	err := r.Random(rand.Reader)
	if err != nil {
		return nil, err
	}

	h := new(GG.G1)
	h.ScalarMult(r, g)

	if !h.IsOnG1() {
		return nil, nil
	}

	return &Params{
		G: g,
		H: h,
	}, nil
}

// Commit computes the Pedersen commit C = mG + oH
func (p *Params) Commit(msg []byte) (*Commitment, *Opening, error) {
	m := utils.HashToScalar(msg, []byte(DST))

	g := new(GG.G1)
	g.ScalarMult(&m, p.G)

	var o GG.Scalar
	_ = o.Random(rand.Reader)

	h := new(GG.G1)
	h.ScalarMult(&o, p.H)

	var c GG.G1
	c.Add(g, h)

	if !c.IsOnG1() || o.IsZero() == 1 {
		return nil, nil, fmt.Errorf("failed to generate commitment")
	}

	return &Commitment{C: &c}, &Opening{O: &o}, nil
}

func (p *Params) Open(msg []byte, commitment *Commitment, opening *Opening) bool {
	m := utils.HashToScalar(msg, []byte(DST))

	g := new(GG.G1)
	g.ScalarMult(&m, p.G)

	h := new(GG.G1)
	h.ScalarMult(opening.O, p.H)

	c := new(GG.G1)
	c.Add(g, h)

	return c.IsEqual(commitment.C)
}
