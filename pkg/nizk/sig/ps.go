// Package implements a PoC in our setting for proving knowledge of a PS signature [1] via a NIZK.

// References:
// [1] https://eprint.iacr.org/2015/525.pdf

package sig

import (
	PS "OPPID/pkg/sign/ps"
	"OPPID/pkg/utils"
	"bytes"
	GG "github.com/cloudflare/circl/ecc/bls12381"
	"log"
)

const DSTStr = "OPPID_BLS12384_XMD:SHA-256_NIZK_PS"

type PublicInput struct {
	psPp *PS.PublicParams
	psPk *PS.PublicKey
}

type Witness struct {
	msg []byte
	sig *PS.Signature
}

type Proof struct {
	rndSig *PS.Signature
	a1     *GG.Gt
	s1     *GG.Scalar
	s2     *GG.Scalar
}

type RandomizedSignature struct {
	BldValue *GG.Scalar // corresponds to t
	Sig      *PS.Signature
}

// Randomize corresponds to Sec. 6.2 of the paper [1, p.9].
func Randomize(sig *PS.Signature) (*GG.Scalar, *PS.Signature) {
	r := utils.GenerateRandomScalar()
	t := utils.GenerateRandomScalar()
	rndSig := new(PS.Signature)

	rndSig.One = utils.GenerateG1Point(r, sig.One) // sig1^r
	r2 := utils.GenerateG1Point(r, sig.Two)        // sig2^r

	t1 := utils.GenerateG1Point(t, rndSig.One) // sig1^rt
	rndSig.Two = utils.AddG1Points(r2, t1)     // sig2^r * sig1^tr

	return t, rndSig // (sig1^r, (sig2 * sig1^BldValue)^r)
}

func Prove(p PublicInput, w Witness) Proof {
	u1 := utils.GenerateRandomScalar()
	u2 := utils.GenerateRandomScalar()
	t, rndSig := Randomize(w.sig)

	var pi Proof
	pi.rndSig = rndSig

	// Announcements
	y := utils.GenerateG2Point(u1, p.psPk.Y)
	g := utils.GenerateG2Point(u2, p.psPk.G)
	yg := utils.AddG2Points(y, g)

	pi.a1 = GG.Pair(rndSig.One, yg)

	// Challenge
	var buf bytes.Buffer

	a1Bytes, _ := pi.a1.MarshalBinary()
	buf.Write(rndSig.One.Bytes())
	buf.Write(rndSig.Two.Bytes())
	buf.Write(a1Bytes)

	z := utils.HashToScalar(buf.Bytes(), []byte(DSTStr))

	// Responses
	m := utils.HashToScalar(w.msg, p.psPp.Dst)

	mz := utils.MulScalars(&m, &z)
	pi.s1 = utils.AddScalars(u1, mz)

	tz := utils.MulScalars(t, &z)
	pi.s2 = utils.AddScalars(u2, tz)

	return pi
}

func Verify(p PublicInput, pi Proof) bool {
	var buf bytes.Buffer

	a1Bytes, _ := pi.a1.MarshalBinary()
	buf.Write(pi.rndSig.One.Bytes())
	buf.Write(pi.rndSig.Two.Bytes())
	buf.Write(a1Bytes)

	z := utils.HashToScalar(buf.Bytes(), []byte(DSTStr))

	z1 := utils.GenerateG1Point(&z, pi.rndSig.Two)

	p1 := GG.Pair(z1, p.psPk.G)

	z2 := utils.GenerateG1Point(&z, pi.rndSig.One)

	p2 := GG.Pair(z2, p.psPk.X)

	p2Inv := new(GG.Gt)
	p2Inv.Inv(p2)

	h1 := new(GG.Gt)
	h1.Mul(p1, p2Inv)

	lhs := new(GG.Gt)
	lhs.Mul(h1, pi.a1)

	y := utils.GenerateG2Point(pi.s1, p.psPk.Y)
	g := utils.GenerateG2Point(pi.s2, p.psPk.G)
	yg := utils.AddG2Points(y, g)

	rhs := GG.Pair(pi.rndSig.One, yg)

	isValid := lhs.IsEqual(rhs)
	if !isValid {
		log.Println("Invalid PublicParams signature")
	}

	return isValid
}
