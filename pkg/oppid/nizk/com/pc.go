// Package provides a NIZK for Pedersen commitments (PC). It is not directly used and is kept here for testing.

package com

import (
	PC "OPPID-artifacts/pkg/oppid/commit/pc"
	"OPPID-artifacts/pkg/oppid/utils"
	"bytes"
	"log"

	GG "github.com/cloudflare/circl/ecc/bls12381"
)

const DST = "OPPID_BLS12384_XMD:SHA-256_NIZK_PC"

type Witness struct {
	msg     []byte
	opening *PC.Opening
}

type PublicInput struct {
	params *PC.PublicParams
	com    *PC.Commitment
}

type Proof struct {
	a1 *GG.G1
	s1 *GG.Scalar
	s2 *GG.Scalar
}

func Prove(p *PublicInput, w *Witness) *Proof {
	u1 := utils.GenerateRandomScalar()
	u2 := utils.GenerateRandomScalar()

	// Announcement
	g := utils.GenerateG1Point(u1, p.params.G)
	h := utils.GenerateG1Point(u2, p.params.H)

	a1 := utils.AddG1Points(g, h)

	// Challenge
	var buff bytes.Buffer

	buff.Write(a1.Bytes())
	buff.Write(p.com.Element.Bytes())

	data := buff.Bytes()

	z := utils.HashToScalar(data, []byte(DST+"Z"))

	// Responses
	m := utils.HashToScalar(w.msg, p.params.Dst)

	mz, err1 := utils.MulScalars(&m, &z)
	s1, err2 := utils.AddScalars(u1, mz)

	oz, err3 := utils.MulScalars(w.opening.Scalar, &z)
	s2, err4 := utils.AddScalars(u2, oz)

	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		log.Fatalf("error generating proof of a message/opening: %v, %v, %v, %v", err1, err2, err3, err4)
	}

	return &Proof{
		a1: a1, s1: s1, s2: s2,
	}
}

func Verify(p *PublicInput, pi *Proof) bool {
	var buf bytes.Buffer

	buf.Write(pi.a1.Bytes())
	buf.Write(p.com.Element.Bytes())

	data := buf.Bytes()

	z := utils.HashToScalar(data, []byte(DST+"Z"))

	g := utils.GenerateG1Point(pi.s1, p.params.G)
	h := utils.GenerateG1Point(pi.s2, p.params.H)

	lhs := utils.AddG1Points(g, h)

	c := utils.GenerateG1Point(&z, p.com.Element)

	rhs := utils.AddG1Points(pi.a1, c)

	isValid := lhs.IsEqual(rhs)
	if !isValid {
		log.Println("Invalid commitment")
	}

	return isValid
}
