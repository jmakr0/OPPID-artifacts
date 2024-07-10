package hash

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

const MaxInputLength = 128

type SHA256Circuit struct {
	PreImage [MaxInputLength]uints.U8 `gnark:",private"`
	Hash     [32]uints.U8             `gnark:",public"`
}

func (c *SHA256Circuit) Define(api frontend.API) error {
	hash, err := sha2.New(api)
	if err != nil {
		return err
	}
	uApi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	hash.Write(c.PreImage[:])
	res := hash.Sum()
	for i := range c.Hash {
		uApi.ByteAssertEq(c.Hash[i], res[i])
	}
	return nil
}
