package dl

import (
	"OPPID/internal/utils"
	"errors"
	GG "github.com/cloudflare/circl/ecc/bls12381"
)

type DLPRF struct {
	K *GG.Scalar
}

func NewDlPRF() (*DLPRF, error) {
	k, err := utils.GenerateRandomScalar()
	if err != nil {
		return nil, errors.New("failed to generate PRF_DL key: " + err.Error())
	}

	return &DLPRF{K: k}, nil
}

func (prf *DLPRF) Eval(msg []byte) *GG.G1 {
	g := new(GG.G1)
	g.Hash(msg, nil)

	h := new(GG.G1)
	h.ScalarMult(prf.K, g)

	return h
}
