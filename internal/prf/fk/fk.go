package fk

import (
	"OPPID/internal/prf/dl"
	"OPPID/internal/prf/hmac256"
	"OPPID/internal/utils"
	GG "github.com/cloudflare/circl/ecc/bls12381"
)

type FK struct {
	PRF   *hmac256.PRF
	DLPRF *dl.DLPRF
}

func New() *FK {
	prf, _ := hmac256.New()
	prfDL, _ := dl.NewDlPRF()

	prf.K, _ = utils.ScalarToBytes(prfDL.K)

	return &FK{
		PRF: prf, DLPRF: prfDL,
	}
}

func (p *FK) Eval(msg, k []byte) *GG.G1 {
	yStdPRF := p.PRF.Eval(k) // y = PRF(k, k)
	evlKey := utils.HashToScalar(yStdPRF, []byte("BLS12384_XMD:SHA-256_EVL_FK"))
	p.DLPRF.K = &evlKey
	return p.DLPRF.Eval(msg)
}
