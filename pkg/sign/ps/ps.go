package ps

import (
	"OPPID/pkg/utils"
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
	ym := utils.MulScalars(k.y, &m)
	exp := utils.AddScalars(k.x, ym) // x+y*m

	sig.Two = utils.GenerateG1Point(exp, sig.One)

	return sig
}

// Verify checks the validity of the given signature for the message.
func (pp *PublicParams) Verify(pk *PublicKey, msg []byte, sig Signature) bool {
	if !sig.One.IsOnG1() || sig.One.IsIdentity() {
		log.Fatalf("Error verifying psPk signature: sigma one not on G1 curve or is identity")
	}

	m := utils.HashToScalar(msg, pp.Dst)
	Ym := utils.GenerateG2Point(&m, pk.Y)
	XYm := utils.AddG2Points(pk.X, Ym)

	lhs := GG.Pair(sig.One, XYm)
	rhs := GG.Pair(sig.Two, pk.G)

	return lhs.IsEqual(rhs)
}
