package nizk

import (
	PC "OPPID/internal/commit/pedersen"
	"OPPID/internal/sign/ps"
	"OPPID/internal/utils"
	"bytes"
	GG "github.com/cloudflare/circl/ecc/bls12381"
	"log"
)

const DST = "OPPID_BLS12384_XMD:SHA-256_NIZK"

type Witnesses struct {
	Msg     []byte
	Sig     *ps.Signature
	Opening *PC.Opening
}

type PublicInputs struct {
	PSParams *ps.Params
	PCParams *PC.Params
	Com      *PC.Commitment
}

type Proof struct {
	sig *ps.Signature // randomized signature
	a1  *GG.G1
	a2  *GG.Gt
	s1  *GG.Scalar
	s2  *GG.Scalar
	s3  *GG.Scalar
}

func New(w *Witnesses, pubInput *PublicInputs, aux []byte) *Proof {
	u1, _ := utils.GenerateRandomScalar() // for commitment
	u2, _ := utils.GenerateRandomScalar() // for commitment
	u3, _ := utils.GenerateRandomScalar() // for signature

	// commitment announcement
	g := new(GG.G1)
	g.ScalarMult(u1, pubInput.PCParams.G)

	h := new(GG.G1)
	h.ScalarMult(u2, pubInput.PCParams.H)

	a1 := new(GG.G1)
	a1.Add(g, h) // a1 = g^u1 * h^u2

	// signature announcement
	randSig := randomizePSSignature(w.Sig)

	// Moved to G2 before calculating pairing
	rSig2 := new(GG.G2)
	rSig2.ScalarMult(u1, pubInput.PSParams.Y)

	tSig2 := new(GG.G2)
	tSig2.ScalarMult(u3, pubInput.PSParams.G)

	sig2 := new(GG.G2)
	sig2.Add(rSig2, tSig2)

	a2 := GG.Pair(randSig.randSig.Sig1, sig2)

	// Challenge
	var buf bytes.Buffer

	buf.WriteString(pubInput.Com.C.String())
	buf.WriteString(a1.String())
	buf.WriteString(a2.String())
	buf.Write(aux)

	data := buf.Bytes()

	z := utils.HashToScalar(data, []byte(DST)) // challenge is hash of data

	// Responses
	m := utils.HashToScalar(w.Msg, []byte(PC.DST))
	mz := new(GG.Scalar)
	mz.Mul(&m, &z)

	s1 := new(GG.Scalar)
	s1.Add(u1, mz)

	o := new(GG.Scalar)
	o.Mul(w.Opening.O, &z)

	s2 := new(GG.Scalar)
	s2.Add(u2, o)

	tz := new(GG.Scalar)
	tz.Mul(randSig.t, &z)

	s3 := new(GG.Scalar)
	s3.Add(u3, tz)

	return &Proof{
		sig: randSig.randSig,
		a1:  a1,
		a2:  a2,
		s1:  s1,
		s2:  s2,
		s3:  s3,
	}
}

func Verify(pi *Proof, pubInput *PublicInputs, aux []byte) bool {
	var buff bytes.Buffer

	buff.WriteString(pubInput.Com.C.String())
	buff.WriteString(pi.a1.String())
	buff.WriteString(pi.a2.String())
	buff.Write(aux)

	data := buff.Bytes()

	z := utils.HashToScalar(data, []byte(DST))

	// Verify commitment
	g := new(GG.G1)
	g.ScalarMult(pi.s1, pubInput.PCParams.G)

	h := new(GG.G1)
	h.ScalarMult(pi.s2, pubInput.PCParams.H)

	lhs1 := new(GG.G1)
	lhs1.Add(g, h) // lhs1 = g^s1 * h^s2 = g^(u1+m*z) * h^(u2+o*z)

	c := new(GG.G1)
	c.ScalarMult(&z, pubInput.Com.C)

	rhs1 := new(GG.G1)
	rhs1.Add(c, pi.a1) // rhs1 = com^z * a1 = g^(m*z+u1) * h^(o*z+u2)

	validCommitment := lhs1.IsEqual(rhs1)
	if !validCommitment {
		log.Println("Invalid commitment")
	}

	// Verify signature
	sig1z := new(GG.G1)
	sig1z.ScalarMult(&z, pi.sig.Sig1)

	sig2z := new(GG.G1)
	sig2z.ScalarMult(&z, pi.sig.Sig2)

	lhsP1 := GG.Pair(sig1z, pubInput.PSParams.X)
	lhsP2 := GG.Pair(sig2z, pubInput.PSParams.G)

	inv := new(GG.Gt)
	inv.Inv(lhsP1)

	lhsP3 := new(GG.Gt)
	lhsP3.Mul(lhsP2, inv)

	lhsP4 := new(GG.Gt)
	lhsP4.Mul(lhsP3, pi.a2)

	gt := new(GG.G2)
	gt.ScalarMult(pi.s3, pubInput.PSParams.G)

	ym := new(GG.G2)
	ym.ScalarMult(pi.s1, pubInput.PSParams.Y)

	rhsG2 := new(GG.G2)
	rhsG2.Add(ym, gt)

	rhsP1 := GG.Pair(pi.sig.Sig1, rhsG2)

	validSignature := lhsP4.IsEqual(rhsP1)
	if !validSignature {
		log.Println("Invalid signature")
	}

	return validSignature && validCommitment
}
