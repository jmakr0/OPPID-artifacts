package nizk

import (
	"OPPID/internal/commit/pedersen"
	"OPPID/internal/sign/ps"
	"OPPID/internal/utils"
	"bytes"
	GG "github.com/cloudflare/circl/ecc/bls12381"
	"log"
)

type RandomizedPSSignature struct {
	t   *GG.Scalar
	sig *ps.Signature
}

// Corresponds to 6.2: Proving Knowledge of a Signature
func randomizePSSignature(psSig *ps.Signature) *RandomizedPSSignature {
	r, _ := utils.GenerateRandomScalar()
	r1 := new(GG.G1)
	r1.ScalarMult(r, psSig.Sig1) // sig1^r

	r2 := new(GG.G1)
	r2.ScalarMult(r, psSig.Sig2) // sig2^r

	t, _ := utils.GenerateRandomScalar()
	t1 := new(GG.G1)
	t1.ScalarMult(t, r1) // sig1^rt

	t2 := new(GG.G1)
	t2.Add(r2, t1) // sig2^r * sig1^tr

	sig := &ps.Signature{Sig1: r1, Sig2: t2} // sig' = (sig1^r, (sig2 * sig1^t)^r)

	return &RandomizedPSSignature{t: t, sig: sig}
}

type Witnesses struct {
	Msg     []byte
	Sig     *ps.Signature
	Opening *pedersen.Opening
}

type PublicInputs struct {
	PSParams *ps.Params
	PCParams *pedersen.Params
	Com      *pedersen.Commitment
}

type Proof struct {
	sig        *ps.Signature // randomized signature
	anCom      *GG.G1
	anSig      *GG.Gt
	resMsg     *GG.Scalar
	resOpening *GG.Scalar
	resT       *GG.Scalar
}

func New(w *Witnesses, pubInput *PublicInputs, aux []byte) *Proof {
	r, _ := utils.GenerateRandomScalar()

	// commitment announcement
	gm := new(GG.G1)
	gm.ScalarMult(r, pubInput.PCParams.G)

	h, _ := utils.GenerateRandomScalar()
	ho := new(GG.G1)
	ho.ScalarMult(h, pubInput.PCParams.H)

	anCom := new(GG.G1)
	anCom.Add(gm, ho)

	// signature announcement
	randSig := randomizePSSignature(w.Sig)
	tScalar, _ := utils.GenerateRandomScalar()

	// Moved to G2 before calculating pairing
	rSig2 := new(GG.G2)
	rSig2.ScalarMult(r, pubInput.PSParams.Y)

	tSig2 := new(GG.G2)
	tSig2.ScalarMult(tScalar, pubInput.PSParams.G)

	sig2 := new(GG.G2)
	sig2.Add(rSig2, tSig2)

	anSig := GG.Pair(randSig.sig.Sig1, sig2)

	// Challenge
	var challengeBuffer bytes.Buffer

	challengeBuffer.WriteString(pubInput.Com.C.String())
	challengeBuffer.WriteString(anCom.String())
	challengeBuffer.WriteString(anSig.String())
	challengeBuffer.Write(aux)

	challengeData := challengeBuffer.Bytes()

	z := utils.HashToScalar(challengeData, []byte("OPPID_BLS12384_XMD:SHA-256_NIZK"))

	// Responses
	m := utils.HashToScalar(w.Msg, []byte("OPPID_BLS12384_XMD:SHA-256_NIZK"))
	mz := new(GG.Scalar)
	mz.Mul(&m, &z)

	resM := new(GG.Scalar)
	resM.Add(r, mz)

	oz := new(GG.Scalar)
	oz.Mul(w.Opening.O, &z)

	resO := new(GG.Scalar)
	resO.Add(h, oz)

	tz := new(GG.Scalar)
	tz.Mul(randSig.t, &z)

	resT := new(GG.Scalar)
	resT.Add(tScalar, tz)

	return &Proof{
		sig:        randSig.sig,
		anCom:      anCom,
		anSig:      anSig,
		resMsg:     resM,
		resOpening: resO,
		resT:       resT,
	}
}

func Verify(pi *Proof, pubInput *PublicInputs, aux []byte) bool {
	var challengeBuffer bytes.Buffer

	challengeBuffer.WriteString(pubInput.Com.C.String())
	challengeBuffer.WriteString(pi.anCom.String())
	challengeBuffer.WriteString(pi.anSig.String())
	challengeBuffer.Write(aux)

	challengeData := challengeBuffer.Bytes()

	z := utils.HashToScalar(challengeData, []byte("OPPID_BLS12384_XMD:SHA-256_NIZK"))

	// Verify commitment
	gm := new(GG.G1)
	gm.ScalarMult(pi.resMsg, pubInput.PCParams.G)

	ho := new(GG.G1)
	ho.ScalarMult(pi.resOpening, pubInput.PCParams.H)

	lhsCom := new(GG.G1)
	lhsCom.Add(gm, ho)

	cz := new(GG.G1)
	cz.ScalarMult(&z, pubInput.Com.C)

	rhsCom := new(GG.G1)
	rhsCom.Add(cz, pi.anCom)

	validCommitment := lhsCom.IsEqual(rhsCom)
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
	lhsP4.Mul(lhsP3, pi.anSig)

	gt := new(GG.G2)
	gt.ScalarMult(pi.resT, pubInput.PSParams.G)

	ym := new(GG.G2)
	ym.ScalarMult(pi.resMsg, pubInput.PSParams.Y)

	rhsG2 := new(GG.G2)
	rhsG2.Add(ym, gt)

	rhsP1 := GG.Pair(pi.sig.Sig1, rhsG2)

	validSignature := lhsP4.IsEqual(rhsP1)
	if !validSignature {
		log.Println("Invalid signature")
	}

	return validSignature && validCommitment
}
