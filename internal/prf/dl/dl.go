package dl

import (
	"OPPID/internal/utils"
	GG "github.com/cloudflare/circl/ecc/bls12381"
)

const DSTStr = "ABC"

type DLPRF struct {
	K   *GG.Scalar
	DST []byte
}

func New(dst string) *DLPRF {
	k := utils.GenerateRandomScalar()
	prf := &DLPRF{K: k, DST: []byte(dst)}
	if dst == "" {
		prf.DST = []byte(DSTStr)
	}
	return &DLPRF{K: k}
}

func (prf *DLPRF) Eval(msg []byte) *GG.G1 {
	g := new(GG.G1)
	g.Hash(msg, prf.DST)
	return utils.GenerateG1Point(prf.K, g)
}
