package comsig

import (
	PC "OPPID/pkg/commit/pc"
	NIZK_PS "OPPID/pkg/nizk/sig"
	PS "OPPID/pkg/sign/ps"
	"OPPID/pkg/utils"
	"bytes"
	GG "github.com/cloudflare/circl/ecc/bls12381"
	"log"
)

const dstStr = "OPPID_BLS12384_XMD:SHA-256_NIZK_PC_PS_"

type Witnesses struct {
	Msg     []byte
	Sig     *PS.Signature
	Opening *PC.Opening
}

type PublicInputs struct {
	PS  *PS.PublicKey
	PC  *PC.PublicParams
	Com *PC.Commitment
}

type Proof struct {
	sig *PS.Signature // randomized signature
	a1  *GG.G1
	a2  *GG.Gt
	r1  *GG.Scalar
	r2  *GG.Scalar
	r3  *GG.Scalar
}

func challenge(c *PC.Commitment, a1 *GG.G1, a2 *GG.Gt, aux []byte) GG.Scalar {
	var buf bytes.Buffer

	buf.Write(c.Element.Bytes())
	buf.Write(a1.Bytes())
	a2Bytes, err := a2.MarshalBinary()
	if err != nil {
		log.Fatalf("Failed to marshal a2 announcement: %v", err)
	}
	buf.Write(a2Bytes)
	buf.Write(aux)

	data := buf.Bytes()
	return utils.HashToScalar(data, []byte(dstStr))
}

func New(w Witnesses, p PublicInputs, aux []byte, dst []byte) Proof {
	u1 := utils.GenerateRandomScalar() // for commitment
	u2 := utils.GenerateRandomScalar() // for commitment
	u3 := utils.GenerateRandomScalar() // for signature

	t, randSig := NIZK_PS.Randomize(w.Sig)

	var pi Proof
	pi.sig = randSig

	// Announcement commitment
	g := utils.GenerateG1Point(u1, p.PC.G)
	h := utils.GenerateG1Point(u2, p.PC.H)

	pi.a1 = utils.AddG1Points(g, h) // a1 = g^u1 * h^u2

	// Announcement signature

	// Moved to G2 before calculating pairing
	rSig2 := utils.GenerateG2Point(u1, p.PS.Y)
	tSig2 := utils.GenerateG2Point(u3, p.PS.G)
	sig2 := utils.AddG2Points(rSig2, tSig2)

	pi.a2 = GG.Pair(randSig.One, sig2)

	z := challenge(p.Com, pi.a1, pi.a2, aux)

	// Responses
	m := utils.HashToScalar(w.Msg, dst)
	mz := utils.MulScalars(&m, &z)
	pi.r1 = utils.AddScalars(u1, mz)

	o := utils.MulScalars(w.Opening.Scalar, &z)
	pi.r2 = utils.AddScalars(u2, o)

	tz := utils.MulScalars(t, &z)
	pi.r3 = utils.AddScalars(u3, tz)

	return pi
}

func Verify(pi Proof, p PublicInputs, aux []byte) bool {
	z := challenge(p.Com, pi.a1, pi.a2, aux)

	// Verify commitment
	g := utils.GenerateG1Point(pi.r1, p.PC.G)
	h := utils.GenerateG1Point(pi.r2, p.PC.H)

	lhs1 := utils.AddG1Points(g, h) // lhs1 = g^r1 * h^r2 = g^(u1+m*z) * h^(u2+o*z)

	c := utils.GenerateG1Point(&z, p.Com.Element)

	rhs1 := utils.AddG1Points(c, pi.a1) // rhs1 = Com^z * a1 = g^(m*z+u1) * h^(o*z+u2)

	validCommitment := lhs1.IsEqual(rhs1)
	if !validCommitment {
		log.Println("Invalid commitment")
	}

	// Verify signature
	sig1z := utils.GenerateG1Point(&z, pi.sig.One)
	sig2z := utils.GenerateG1Point(&z, pi.sig.Two)

	lhsP1 := GG.Pair(sig1z, p.PS.X)
	lhsP2 := GG.Pair(sig2z, p.PS.G)

	inv := new(GG.Gt)
	inv.Inv(lhsP1)

	lhsP3 := new(GG.Gt)
	lhsP3.Mul(lhsP2, inv)

	lhsP4 := new(GG.Gt)
	lhsP4.Mul(lhsP3, pi.a2)

	gt := utils.GenerateG2Point(pi.r3, p.PS.G)
	ym := utils.GenerateG2Point(pi.r1, p.PS.Y)

	rhsG2 := utils.AddG2Points(ym, gt)

	rhsP1 := GG.Pair(pi.sig.One, rhsG2)

	validSignature := lhsP4.IsEqual(rhsP1)
	if !validSignature {
		log.Println("Invalid signature")
	}

	return validSignature && validCommitment
}
