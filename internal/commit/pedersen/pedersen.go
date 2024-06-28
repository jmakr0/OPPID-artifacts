package pedersen

import (
	utils "OPPID/internal/utils"
	"crypto/rand"
	"fmt"
	GG "github.com/cloudflare/circl/ecc/bls12381"
)

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
func (p *Params) Commit(msg []byte) (GG.G1, GG.Scalar, error) {
	m := utils.HashToScalar(msg)

	g := new(GG.G1)
	g.ScalarMult(m, p.G)

	var o GG.Scalar
	_ = o.Random(rand.Reader)

	h := new(GG.G1)
	h.ScalarMult(&o, p.H)

	var c GG.G1
	c.Add(g, h)

	if !c.IsOnG1() || o.IsZero() == 1 {
		return GG.G1{}, GG.Scalar{}, fmt.Errorf("failed to generate commitment")
	}

	return c, o, nil
}

func (p *Params) Open(msg []byte, com *GG.G1, o *GG.Scalar) bool {
	m := utils.HashToScalar(msg)

	g := new(GG.G1)
	g.ScalarMult(m, p.G)

	h := new(GG.G1)
	h.ScalarMult(o, p.H)

	c := new(GG.G1)
	c.Add(g, h)

	return c.IsEqual(com)
}
