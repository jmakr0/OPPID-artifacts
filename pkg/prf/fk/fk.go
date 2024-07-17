package fk

import (
	DLPRF "OPPID/pkg/prf/dl"
	HMACPRF "OPPID/pkg/prf/hmac256"
	"OPPID/pkg/utils"
	GG "github.com/cloudflare/circl/ecc/bls12381"
)

const dstStr = "OPPID_BLS12384_XMD:SHA-256_FK_"

type Key = HMACPRF.Key

func KeyGen() *Key {
	return HMACPRF.KeyGen()
}

func Eval(k *Key, msg1, msg2 []byte) *GG.G1 {
	y := HMACPRF.Eval(k, msg2)
	key := utils.HashToScalar(y, []byte(dstStr))
	return DLPRF.Eval(&key, msg1)
}
