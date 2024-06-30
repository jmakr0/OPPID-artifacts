package ps

import (
	PS "OPPID/internal/sign/ps"
	"OPPID/internal/utils"
	"bytes"
	GG "github.com/cloudflare/circl/ecc/bls12381"
	"log"
)

const DST = "OPPID_BLS12384_XMD:SHA-256_NIZK_PS"

type PublicInput struct {
	PSParams *PS.Params
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
	t       *GG.Scalar
	randSig *PS.Signature
}

// Corresponds to 6.2: Proving Knowledge of a Signature
func Randomize(psSig *PS.Signature) *RandomizedSignature {
	r, _ := utils.GenerateRandomScalar()
	t, _ := utils.GenerateRandomScalar()

	r1, _ := utils.GenerateG1Point(r, psSig.Sig1) // sig1^r
	//r1 := new(GG.G1)
	//r1.ScalarMult(r, psSig.Sig1)

	r2, _ := utils.GenerateG1Point(r, psSig.Sig2) // sig2^r
	//r2 := new(GG.G1)
	//r2.ScalarMult(r, psSig.Sig2) // sig2^r

	t1, _ := utils.GenerateG1Point(t, r1) // sig1^rt
	//t1 := new(GG.G1)
	//t1.ScalarMult(t, r1) // sig1^rt

	t2, _ := utils.AddG1Points(r2, t1) // sig2^r * sig1^tr
	//t2 := new(GG.G1)
	//t2.Add(r2, t1) // sig2^r * sig1^tr

	randSig := &PS.Signature{Sig1: r1, Sig2: t2} // (sig1^r, (sig2 * sig1^t)^r)

	return &RandomizedSignature{t: t, randSig: randSig}
}

func New(p *PublicInput, w *Witness) *Proof {
	u1, _ := utils.GenerateRandomScalar()
	u2, _ := utils.GenerateRandomScalar()
	randSig := Randomize(w.sig)

	// Announcements
	y, _ := utils.GenerateG2Point(u1, p.PSParams.Y)
	g, _ := utils.GenerateG2Point(u2, p.PSParams.G)

	u3, _ := utils.AddG2Points(y, g)
	//u3 := new(GG.G2)
	//u3.Add(y, g)

	a1 := GG.Pair(randSig.randSig.Sig1, u3)

	// Challenge
	var buff bytes.Buffer

	a1Bytes, _ := a1.MarshalBinary()
	buff.Write(randSig.randSig.Sig1.Bytes())
	buff.Write(randSig.randSig.Sig2.Bytes())
	buff.Write(a1Bytes)

	data := buff.Bytes()
	z := utils.HashToScalar(data, []byte(DST))

	// Responses
	m := utils.HashToScalar(w.msg, []byte(PS.DST))
	mz := new(GG.Scalar)
	mz.Mul(&m, &z)

	s1 := new(GG.Scalar)
	s1.Add(u1, mz)

	tz := new(GG.Scalar)
	tz.Mul(randSig.t, &z)

	s2 := new(GG.Scalar)
	s2.Add(u2, tz)

	return &Proof{
		randSig: randSig.randSig,
		a1:      a1,
		s1:      s1,
		s2:      s2,
	}
}

func Verify(p *PublicInput, pi *Proof) bool {
	var buff bytes.Buffer

	a1Bytes, _ := pi.a1.MarshalBinary()
	buff.Write(pi.randSig.Sig1.Bytes())
	buff.Write(pi.randSig.Sig2.Bytes())
	buff.Write(a1Bytes)

	data := buff.Bytes()
	z := utils.HashToScalar(data, []byte(DST))

	z1 := new(GG.G1)
	z1.ScalarMult(&z, pi.randSig.Sig2)

	p1 := GG.Pair(z1, p.PSParams.G)

	z2 := new(GG.G1)
	z2.ScalarMult(&z, pi.randSig.Sig1)

	p2 := GG.Pair(z2, p.PSParams.X)

	p2Inv := new(GG.Gt)
	p2Inv.Inv(p2)

	h1 := new(GG.Gt)
	h1.Mul(p1, p2Inv)

	lhs := new(GG.Gt)
	lhs.Mul(h1, pi.a1)

	y, _ := utils.GenerateG2Point(pi.s1, p.PSParams.Y)
	//y := new(GG.G2)
	//y.ScalarMult(pi.s1, p.PSParams.Y)

	g, _ := utils.GenerateG2Point(pi.s2, p.PSParams.G)
	//g := new(GG.G2)
	//g.ScalarMult(pi.s2, p.PSParams.G)

	h2 := new(GG.G2)
	h2.Add(y, g)

	rhs := GG.Pair(pi.randSig.Sig1, h2)

	isValid := lhs.IsEqual(rhs)
	if !isValid {
		log.Println("Invalid commitment")
	}

	return isValid
}
