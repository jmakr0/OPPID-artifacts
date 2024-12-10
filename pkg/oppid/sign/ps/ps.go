// Package implements PS signatures [1], used for signatures with efficient proofs of knowledge.

// References:
// [1] https://eprint.iacr.org/2015/525.pdf

package ps

import (
	"OPPID/pkg/oppid/utils"
	GG "github.com/cloudflare/circl/ecc/bls12381"
	"log"
)

const dstStr = "OPPID_BLS12384_XMD:SHA-256_PS_"

type PublicParams struct {
	Dst []byte
}

type PublicKey struct {
	G *GG.G2
	X *GG.G2
	Y *GG.G2
}

type PrivateKey struct {
	x  *GG.Scalar
	y  *GG.Scalar
	Pk *PublicKey
}

type Signature struct {
	One *GG.G1
	Two *GG.G1
}

func Setup(dst []byte) *PublicParams {
	if dst == nil {
		return &PublicParams{Dst: []byte(dstStr)}
	}
	return &PublicParams{dst}
}

func (pp *PublicParams) KeyGen() (*PrivateKey, *PublicKey) {
	x := utils.GenerateRandomScalar()
	y := utils.GenerateRandomScalar()

	g := GG.G2Generator()

	X := utils.GenerateG2Point(x, g)
	Y := utils.GenerateG2Point(y, g)

	pk := &PublicKey{g, X, Y}

	return &PrivateKey{x, y, pk}, pk
}

func (pp *PublicParams) Sign(k *PrivateKey, msg []byte) Signature {
	var sig Signature

	u := utils.GenerateRandomScalar()
	sig.One = utils.GenerateG1Point(u, GG.G1Generator())

	m := utils.HashToScalar(msg, pp.Dst)
	ym, err1 := utils.MulScalars(k.y, &m)
	exp, err2 := utils.AddScalars(k.x, ym) // x+y*m

	if err1 != nil || err2 != nil {
		log.Fatalf("error generating PS signature: multiplication %v, addition %v", err1, err2)
	}

	sig.Two = utils.GenerateG1Point(exp, sig.One)

	return sig
}

func (pp *PublicParams) Verify(pk *PublicKey, msg []byte, sig Signature) bool {
	if !sig.One.IsOnG1() || sig.One.IsIdentity() {
		log.Fatalf("Error verifying PS signature: sigma one not on G1 curve or is identity")
	}

	m := utils.HashToScalar(msg, pp.Dst)
	Ym := utils.GenerateG2Point(&m, pk.Y)
	XYm := utils.AddG2Points(pk.X, Ym)

	lhs := GG.Pair(sig.One, XYm)
	rhs := GG.Pair(sig.Two, pk.G)

	return lhs.IsEqual(rhs)
}
