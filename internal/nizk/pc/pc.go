package pc

import (
	PC "OPPID/internal/commit/pedersen"
	"OPPID/internal/utils"
	"bytes"
	GG "github.com/cloudflare/circl/ecc/bls12381"
	"log"
)

type Witness struct {
	msg     []byte
	opening *PC.Opening
}

type PublicInput struct {
	params *PC.Params
	com    *PC.Commitment
}

type Proof struct {
	A  *GG.G1
	s1 *GG.Scalar
	s2 *GG.Scalar
}

func New(p *PublicInput, w *Witness) *Proof {
	r1, _ := utils.GenerateRandomScalar()
	r2, _ := utils.GenerateRandomScalar()

	log.Println(p.params.G.String())

	// Announcement
	g := new(GG.G1)
	g.ScalarMult(r1, p.params.G)

	log.Println(p.params.G.String())

	log.Println(p.params.H.String())

	h := new(GG.G1)
	h.ScalarMult(r2, p.params.H)

	log.Println(p.params.H.String())

	a := new(GG.G1)
	a.Add(g, h)

	// Challenge
	var challengeBuffer bytes.Buffer

	challengeBuffer.Write(a.Bytes())
	challengeBuffer.Write(p.com.C.Bytes())

	challengeData := challengeBuffer.Bytes()

	z := utils.HashToScalar(challengeData, []byte("OPPID_BLS12384_XMD:SHA-256_NIZK_PC"))

	// Responses
	m := utils.HashToScalar(w.msg, []byte(PC.DST))
	mz := new(GG.Scalar)
	mz.Mul(&m, &z)

	s1 := new(GG.Scalar)
	s1.Add(r1, mz)

	oz := new(GG.Scalar)
	oz.Mul(w.opening.O, &z)

	s2 := new(GG.Scalar)
	s2.Add(r2, oz)

	return &Proof{
		A: a, s1: s1, s2: s2,
	}
}

func Verify(p *PublicInput, pi *Proof) bool {
	var challengeBuffer bytes.Buffer

	challengeBuffer.Write(pi.A.Bytes())
	challengeBuffer.Write(p.com.C.Bytes())

	challengeData := challengeBuffer.Bytes()

	z := utils.HashToScalar(challengeData, []byte("OPPID_BLS12384_XMD:SHA-256_NIZK_PC"))

	log.Println(p.params.G.String())

	g := new(GG.G1)
	g.ScalarMult(pi.s1, p.params.G)

	log.Println(p.params.G.String())

	h := new(GG.G1)
	h.ScalarMult(pi.s2, p.params.H)

	lhs := new(GG.G1)
	lhs.Add(g, h)

	c := new(GG.G1)
	c.ScalarMult(&z, p.com.C)

	rhs := new(GG.G1)
	rhs.Add(pi.A, c)

	log.Println(lhs.String(), "|", rhs.String())

	validCommitment := lhs.IsEqual(rhs)
	if !validCommitment {
		log.Println("Invalid commitment")
	}

	return validCommitment
}
