package fk

import (
	DL_PRF "OPPID/pkg/prf/dl"
	HMAC_PRF "OPPID/pkg/prf/hmac256"
	"OPPID/pkg/utils"
	GG "github.com/cloudflare/circl/ecc/bls12381"
)

const dstStr = "OPPID_BLS12384_XMD:SHA-256_FK_"

type Key = HMAC_PRF.Key

func KeyGen() *Key {
	return HMAC_PRF.KeyGen()
}

func Eval(k *Key, msg1, msg2 []byte) *GG.G1 {
	y := HMAC_PRF.Eval(k, msg2)
	key := utils.HashToScalar(y, []byte(dstStr))
	return DL_PRF.Eval(&key, msg1)
}
