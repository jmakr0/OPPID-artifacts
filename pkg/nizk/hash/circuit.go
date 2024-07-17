// The circuit for proving statements hash_pub = H( H(s || x) || y), where x and y are witnesses and s a shared input

package hash

import (
	"crypto/sha256"
	"errors"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

const MaxInputLength = 128
const MaxOutputLength = 32

// Circuit for proving Image = H( H(SharedInput || X) || Y) with H = sha256
type Circuit struct {
	X           [MaxInputLength]uints.U8  `gnark:",private"`
	Y           [MaxInputLength]uints.U8  `gnark:",private"`
	SharedInput [MaxInputLength]uints.U8  `gnark:",public"`
	Image       [MaxOutputLength]uints.U8 `gnark:",public"`
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
	innerPreimage := append(c.SharedInput[:], c.X[:]...)
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

// BuildCircuitInputs returns the circuit inputs padded to the correct length in the order: x, y, shared input, image
func BuildCircuitInputs(x, y, sharedInput []byte) ([MaxInputLength]byte, [MaxInputLength]byte, [MaxInputLength]byte, [MaxOutputLength]byte, error) {
	if len(x) > MaxInputLength || len(y) > MaxInputLength || len(sharedInput) > MaxInputLength {
		return [MaxInputLength]byte{}, [MaxInputLength]byte{}, [MaxInputLength]byte{}, [MaxOutputLength]byte{}, errors.New("invalid input length")
	}

	var sharedInputBytes [MaxInputLength]byte
	copy(sharedInputBytes[:], sharedInput)

	var xBytes [MaxInputLength]byte
	copy(xBytes[:], x)

	bytes := append(sharedInputBytes[:], xBytes[:]...)
	innerHash := sha256.Sum256(bytes)

	var yBytes [MaxInputLength]byte
	copy(yBytes[:], y)

	preimage := append(innerHash[:], yBytes[:]...)
	hash := sha256.Sum256(preimage)

	return xBytes, yBytes, sharedInputBytes, hash, nil
}
