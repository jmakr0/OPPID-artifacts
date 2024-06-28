package ps

import (
	"OPPID/internal/utils"
	"errors"
	GG "github.com/cloudflare/circl/ecc/bls12381"
)

// todo: split into public/private values
type Params struct {
	g *GG.G2
	x *GG.Scalar
	y *GG.Scalar
	X *GG.G2
	Y *GG.G2
}

type Signature struct {
	Sig1 *GG.G1
	Sig2 *GG.G1
}

// New initializes the parameters for the signature scheme.
func New() (*Params, error) {
	g := GG.G2Generator()

	x, err := utils.GenerateRandomScalar()
	if err != nil {
		return nil, errors.New("failed to generate random scalar x: " + err.Error())
	}

	X, err := utils.GenerateG2Point(x, g)
	if err != nil {
		return nil, errors.New("failed to generate G2 point X: " + err.Error())
	}

	y, err := utils.GenerateRandomScalar()
	if err != nil {
		return nil, errors.New("failed to generate random scalar y: " + err.Error())
	}

	Y, err := utils.GenerateG2Point(y, g)
	if err != nil {
		return nil, errors.New("failed to generate G2 point Y: " + err.Error())
	}

	return &Params{
		g: g,
		x: x,
		y: y,
		X: X,
		Y: Y,
	}, nil
}

// Sign generates a signature for the given message.
func (p *Params) Sign(msg []byte) (*Signature, error) {
	r, err := utils.GenerateRandomScalar()
	if err != nil {
		return nil, errors.New("failed to generate random scalar r: " + err.Error())
	}

	h1 := new(GG.G1)
	h1.ScalarMult(r, GG.G1Generator())
	if !h1.IsOnG1() {
		return nil, errors.New("generated h1 is not on G1 curve")
	}

	m := utils.HashToScalar(msg)
	ym := new(GG.Scalar)
	ym.Mul(p.y, m)

	e := new(GG.Scalar)
	e.Add(p.x, ym) // x+y*m

	h2 := new(GG.G1)
	h2.ScalarMult(e, h1)

	return &Signature{
		Sig1: h1,
		Sig2: h2,
	}, nil
}

// Verify checks the validity of the given signature for the message.
func (p *Params) Verify(msg []byte, sig Signature) (bool, error) {
	if !sig.Sig1.IsOnG1() || sig.Sig1.IsIdentity() {
		return false, errors.New("invalid Sig1: not on G1 curve or is identity")
	}

	m := utils.HashToScalar(msg)
	Ym := new(GG.G2)
	Ym.ScalarMult(m, p.Y)

	XYm := new(GG.G2)
	XYm.Add(p.X, Ym)

	lhs := GG.Pair(sig.Sig1, XYm)
	rhs := GG.Pair(sig.Sig2, p.g)

	return lhs.IsEqual(rhs), nil
}
