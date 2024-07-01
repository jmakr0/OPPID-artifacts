package fk

import (
	DL_PRF "OPPID/internal/prf/dl"
	PRF "OPPID/internal/prf/hmac256"
	"OPPID/internal/utils"
	GG "github.com/cloudflare/circl/ecc/bls12381"
)

type FK struct {
	HmacPRF *PRF.PRF
	DlPRF   *DL_PRF.DLPRF
}

func New() *FK {
	prfHmac := PRF.New()
	prfDL := DL_PRF.New("")
	return &FK{HmacPRF: prfHmac, DlPRF: prfDL}
}

// todo: fix DST
func (p *FK) Eval(msg1, msg2 []byte) *GG.G1 {
	y := p.HmacPRF.Eval(msg2) // y = HmacPRF(msg2, msg2)
	k := utils.HashToScalar(y, []byte("BLS12384_XMD:SHA-256_EVL_FK"))
	p.DlPRF.K = &k
	return p.DlPRF.Eval(msg1)
}
