// The circuit for proving statements hash_pub = H( H(in_pub || x) || y), where x and y are witnesses.

package hash

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

const MaxInputLength = 128
const OutputLength = 32

// Circuit for proving Image = H( H(PreimagePub || X) || Y) with H = sha256
type Circuit struct {
	X           [MaxInputLength]uints.U8 `gnark:",private"`
	Y           [MaxInputLength]uints.U8 `gnark:",private"`
	PreimagePub [MaxInputLength]uints.U8 `gnark:",public"`
	Image       [OutputLength]uints.U8   `gnark:",public"`
}

func (c *Circuit) Define(api frontend.API) error {
	uApi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	innerHash, err := sha2.New(api)
	if err != nil {
		return err
	}
	innerPreimage := append(c.PreimagePub[:], c.X[:]...)
	innerHash.Write(innerPreimage)
	innerImage := innerHash.Sum()

	hash, err := sha2.New(api)
	if err != nil {
		return err
	}
	preimage := append(innerImage[:], c.Y[:]...)
	hash.Write(preimage)
	image := hash.Sum()

	for i := range c.Image {
		uApi.ByteAssertEq(c.Image[i], image[i])
	}
	return nil
}
