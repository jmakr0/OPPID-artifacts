package dl

import (
	"OPPID-artifacts/pkg/oppid/utils"

	GG "github.com/cloudflare/circl/ecc/bls12381"
)

const dstStr = "OPPID_BLS12384_XMD:SHA-256_DL_PRF"

type Key = GG.Scalar

func KeyGen() *Key {
	return utils.GenerateRandomScalar()
}

func Eval(k *Key, msg []byte) *GG.G1 {
	g := new(GG.G1)
	g.Hash(msg, []byte(dstStr))
	return utils.GenerateG1Point(k, g)
}
