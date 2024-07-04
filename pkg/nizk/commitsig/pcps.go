package commitsig

import (
	PC "OPPID/pkg/commit/pc"
	NIZK_PS "OPPID/pkg/nizk/sig"
	"OPPID/pkg/sign/ps"
	"OPPID/pkg/utils"
	"bytes"
	GG "github.com/cloudflare/circl/ecc/bls12381"
	"log"
)

const DSTStr = "OPPID_BLS12384_XMD:SHA-256_NIZK_PC_PS"

type Witnesses struct {
	Msg     []byte
	Sig     *ps.Signature
	Opening *PC.Opening
}

type PublicInputs struct {
	PSParams *ps.PublicParams
	PCParams *PC.PublicParams
	Com      *PC.Commitment
}

type Proof struct {
	sig *ps.Signature // randomized signature
	a1  *GG.G1
	a2  *GG.Gt
	r1  *GG.Scalar
	r2  *GG.Scalar
	r3  *GG.Scalar
}

func New(w *Witnesses, p *PublicInputs, aux []byte) *Proof {
	u1 := utils.GenerateRandomScalar() // for commitment
	u2 := utils.GenerateRandomScalar() // for commitment
	u3 := utils.GenerateRandomScalar() // for signature
	randSig := NIZK_PS.Randomize(w.Sig)

	// commitment announcement
	g := utils.GenerateG1Point(u1, p.PCParams.G)
	h := utils.GenerateG1Point(u2, p.PCParams.H)
	a1 := utils.AddG1Points(g, h) // a1 = g^u1 * h^u2

	// signature announcement

	// Moved to G2 before calculating pairing
	rSig2 := utils.GenerateG2Point(u1, p.PSParams.Y)
	tSig2 := utils.GenerateG2Point(u3, p.PSParams.G)
	sig2 := utils.AddG2Points(rSig2, tSig2)

	a2 := GG.Pair(randSig.Sig.One, sig2)

	// Challenge
	var buf bytes.Buffer

	buf.WriteString(p.Com.Element.String())
	buf.WriteString(a1.String())
	buf.WriteString(a2.String())
	buf.Write(aux)

	data := buf.Bytes()
	z := utils.HashToScalar(data, []byte(DSTStr)) // challenge is hash of data

	// Responses
	m := utils.HashToScalar(w.Msg, p.PCParams.DST)

	mz := utils.MulScalars(&m, &z)
	s1 := utils.AddScalars(u1, mz)

	o := utils.MulScalars(w.Opening.Scalar, &z)
	s2 := utils.AddScalars(u2, o)

	tz := utils.MulScalars(randSig.BldValue, &z)
	s3 := utils.AddScalars(u3, tz)

	return &Proof{
		sig: randSig.Sig,
		a1:  a1,
		a2:  a2,
		r1:  s1,
		r2:  s2,
		r3:  s3,
	}
}

func Verify(pi *Proof, pubInput *PublicInputs, aux []byte) bool {
	var buff bytes.Buffer

	buff.WriteString(pubInput.Com.Element.String())
	buff.WriteString(pi.a1.String())
	buff.WriteString(pi.a2.String())
	buff.Write(aux)

	data := buff.Bytes()

	z := utils.HashToScalar(data, []byte(DSTStr))

	// Verify commitment
	g := utils.GenerateG1Point(pi.r1, pubInput.PCParams.G)
	h := utils.GenerateG1Point(pi.r2, pubInput.PCParams.H)

	lhs1 := utils.AddG1Points(g, h) // lhs1 = g^r1 * h^r2 = g^(u1+m*z) * h^(u2+o*z)

	c := utils.GenerateG1Point(&z, pubInput.Com.Element)

	rhs1 := utils.AddG1Points(c, pi.a1) // rhs1 = com^z * a1 = g^(m*z+u1) * h^(o*z+u2)

	validCommitment := lhs1.IsEqual(rhs1)
	if !validCommitment {
		log.Println("Invalid commitment")
	}

	// Verify signature
	sig1z := utils.GenerateG1Point(&z, pi.sig.One)

	sig2z := utils.GenerateG1Point(&z, pi.sig.Two)

	lhsP1 := GG.Pair(sig1z, pubInput.PSParams.X)
	lhsP2 := GG.Pair(sig2z, pubInput.PSParams.G)

	inv := new(GG.Gt)
	inv.Inv(lhsP1)

	lhsP3 := new(GG.Gt)
	lhsP3.Mul(lhsP2, inv)

	lhsP4 := new(GG.Gt)
	lhsP4.Mul(lhsP3, pi.a2)

	gt := utils.GenerateG2Point(pi.r3, pubInput.PSParams.G)
	ym := utils.GenerateG2Point(pi.r1, pubInput.PSParams.Y)

	rhsG2 := utils.AddG2Points(ym, gt)

	rhsP1 := GG.Pair(pi.sig.One, rhsG2)

	validSignature := lhsP4.IsEqual(rhsP1)
	if !validSignature {
		log.Println("Invalid signature")
	}

	return validSignature && validCommitment
}
