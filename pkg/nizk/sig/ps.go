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
	randSig *PS.Signature
	a1      *GG.Gt
	s1      *GG.Scalar
	s2      *GG.Scalar
}

type RandomizedSignature struct {
	BldValue *GG.Scalar // corresponds to t
	Sig      *PS.Signature
}

// Randomize corresponds to 6.2: Proving Knowledge of a Signature
func Randomize(psSig *PS.Signature) *RandomizedSignature {
	r := utils.GenerateRandomScalar()
	t := utils.GenerateRandomScalar()

	r1 := utils.GenerateG1Point(r, psSig.One) // sig1^r
	r2 := utils.GenerateG1Point(r, psSig.Two) // sig2^r
	t1 := utils.GenerateG1Point(t, r1)        // sig1^rt
	t2 := utils.AddG1Points(r2, t1)           // sig2^r * sig1^tr

	randSig := &PS.Signature{One: r1, Two: t2} // (sig1^r, (sig2 * sig1^BldValue)^r)

	return &RandomizedSignature{BldValue: t, Sig: randSig}
}

func New(p *PublicInput, w *Witness) *Proof {
	u1 := utils.GenerateRandomScalar()
	u2 := utils.GenerateRandomScalar()
	randSig := Randomize(w.sig)

	// Announcements
	y := utils.GenerateG2Point(u1, p.psPk.Y)
	g := utils.GenerateG2Point(u2, p.psPk.G)
	yg := utils.AddG2Points(y, g)

	a1 := GG.Pair(randSig.Sig.One, yg)

	// Challenge
	var buff bytes.Buffer

	a1Bytes, _ := a1.MarshalBinary()
	buff.Write(randSig.Sig.One.Bytes())
	buff.Write(randSig.Sig.Two.Bytes())
	buff.Write(a1Bytes)

	data := buff.Bytes()
	z := utils.HashToScalar(data, []byte(DSTStr))

	// Responses
	m := utils.HashToScalar(w.msg, p.psPp.Dst)

	mz := utils.MulScalars(&m, &z)
	s1 := utils.AddScalars(u1, mz)

	tz := utils.MulScalars(randSig.BldValue, &z)
	s2 := utils.AddScalars(u2, tz)

	return &Proof{
		randSig: randSig.Sig,
		a1:      a1,
		s1:      s1,
		s2:      s2,
	}
}

func Verify(p *PublicInput, pi *Proof) bool {
	var buff bytes.Buffer

	a1Bytes, _ := pi.a1.MarshalBinary()
	buff.Write(pi.randSig.One.Bytes())
	buff.Write(pi.randSig.Two.Bytes())
	buff.Write(a1Bytes)

	data := buff.Bytes()
	z := utils.HashToScalar(data, []byte(DSTStr))

	z1 := utils.GenerateG1Point(&z, pi.randSig.Two)

	p1 := GG.Pair(z1, p.psPk.G)

	z2 := utils.GenerateG1Point(&z, pi.randSig.One)

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

	rhs := GG.Pair(pi.randSig.One, yg)

	isValid := lhs.IsEqual(rhs)
	if !isValid {
		log.Println("Invalid PublicParams signature")
	}

	return isValid
}
