package utils

import (
	"testing"
)

func TestHashToScalar(t *testing.T) {
	data := []byte("test data")
	scalar1 := HashToScalar(data, []byte("DST_TEST"))
	scalar2 := HashToScalar(data, []byte("DST_TEST"))

	if scalar1.IsEqual(&scalar2) != 1 {
		t.Fatalf("Hash to scalar should produce consistent results for the same input")
	}
}
