package ps

import (
	"OPPID/internal/utils"
	"errors"
	GG "github.com/cloudflare/circl/ecc/bls12381"
)

const DSTStr = "OPPID_BLS12384_XMD:SHA-256_PS"

type PS struct {
	G   *GG.G2 // corresponds to g tilde
	x   *GG.Scalar
	y   *GG.Scalar
	X   *GG.G2
	Y   *GG.G2
	DST []byte
}

type Signature struct {
	One *GG.G1
	Two *GG.G1
}

// New initializes the parameters for the signature scheme.
func New(dst string) *PS {
	g := GG.G2Generator()

	x := utils.GenerateRandomScalar()
	X := utils.GenerateG2Point(x, g)

	y := utils.GenerateRandomScalar()
	Y := utils.GenerateG2Point(y, g)

	ps := &PS{G: g, x: x, y: y, X: X, Y: Y, DST: []byte(dst)}
	if dst == "" {
		ps.DST = []byte(DSTStr)
	}

	return ps
}

// Sign generates a signature for the given message.
func (p *PS) Sign(msg []byte) *Signature {
	u := utils.GenerateRandomScalar()

	sig1 := utils.GenerateG1Point(u, GG.G1Generator())

	m := utils.HashToScalar(msg, p.DST)

	ym := utils.MulScalars(p.y, &m)
	exp := utils.AddScalars(p.x, ym) // x+y*m

	sig2 := utils.GenerateG1Point(exp, sig1)

	return &Signature{One: sig1, Two: sig2}
}

// Verify checks the validity of the given signature for the message.
func (p *PS) Verify(msg []byte, sig Signature) (bool, error) {
	if !sig.One.IsOnG1() || sig.One.IsIdentity() {
		return false, errors.New("invalid One: not on G1 curve or is identity")
	}

	m := utils.HashToScalar(msg, p.DST)
	Ym := utils.GenerateG2Point(&m, p.Y)

	XYm := utils.AddG2Points(p.X, Ym)

	lhs := GG.Pair(sig.One, XYm)
	rhs := GG.Pair(sig.Two, p.G)

	return lhs.IsEqual(rhs), nil
}
