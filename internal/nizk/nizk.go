package nizk

import (
	"OPPID/internal/commit/pedersen"
	"OPPID/internal/sign/ps"
	"OPPID/internal/utils"
	GG "github.com/cloudflare/circl/ecc/bls12381"
)

type RandomizedPSSignature struct {
	t   *GG.Scalar
	sig *ps.Signature
}

// Corresponds to 6.2: Proving Knowledge of a Signature
// sig' = (sig1^r, (sig2 * sig1^t)^r)
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

	sig := &ps.Signature{Sig1: r1, Sig2: t2}

	return &RandomizedPSSignature{t: t, sig: sig}
}

type NIZK struct {
}

type Witnesses struct {
	Msg     []byte
	Sig     *ps.Signature
	Opening *pedersen.Opening
}

type PublicInputs struct {
	PSPublicParams *ps.Params
	PCPublicParams *pedersen.Params
	Com            *pedersen.Commitment
}

func New(w *Witnesses, pubInput *PublicInputs, aux []byte) *NIZK {
	// commitment announcements
	anRid, _ := utils.GenerateRandomScalar()
	anH, _ := utils.GenerateRandomScalar()
	
	return &NIZK{}
}

func Verify(pi *NIZK, pubInput *PublicInputs, aux []byte) bool {

	return false
}
