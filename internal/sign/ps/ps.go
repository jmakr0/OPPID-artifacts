package ps

import (
	"OPPID/internal/utils"
	"errors"
	GG "github.com/cloudflare/circl/ecc/bls12381"
)

const DST = "OPPID_BLS12384_XMD:SHA-256_PS"

// todo: split into public/private values
type Params struct {
	G *GG.G2 // corresponds to g tilde
	x *GG.Scalar
	y *GG.Scalar
	X *GG.G2
	Y *GG.G2
}

type Signature struct {
	One *GG.G1
	Two *GG.G1
}

// New initializes the parameters for the signature scheme.
func New() *Params {
	g := GG.G2Generator()

	x := utils.GenerateRandomScalar()
	X := utils.GenerateG2Point(x, g)

	y := utils.GenerateRandomScalar()
	Y := utils.GenerateG2Point(y, g)

	return &Params{
		G: g,
		x: x,
		y: y,
		X: X,
		Y: Y,
	}
}

// Sign generates a signature for the given message.
func (p *Params) Sign(msg []byte) (*Signature, error) {
	u := utils.GenerateRandomScalar()

	h1 := utils.GenerateG1Point(u, GG.G1Generator())

	m := utils.HashToScalar(msg, []byte(DST))
	ym := utils.MulScalars(p.y, &m)

	e := utils.AddScalars(p.x, ym) // x+y*m

	h2 := utils.GenerateG1Point(e, h1)

	return &Signature{
		One: h1,
		Two: h2,
	}, nil
}

// Verify checks the validity of the given signature for the message.
func (p *Params) Verify(msg []byte, sig Signature) (bool, error) {
	if !sig.One.IsOnG1() || sig.One.IsIdentity() {
		return false, errors.New("invalid One: not on G1 curve or is identity")
	}

	m := utils.HashToScalar(msg, []byte(DST))
	Ym := utils.GenerateG2Point(&m, p.Y)

	XYm := utils.AddG2Points(p.X, Ym)

	lhs := GG.Pair(sig.One, XYm)
	rhs := GG.Pair(sig.Two, p.G)

	return lhs.IsEqual(rhs), nil
}
