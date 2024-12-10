package fk

import (
	"testing"
)

func TestFKEval(t *testing.T) {
	key := KeyGen()

	msg1 := []byte("Inner test message")
	msg2 := []byte("Outer test message")

	y := Eval(key, msg1, msg2)
	if y.IsIdentity() || !y.IsOnG1() {
		t.Fatalf("output is invalid")
	}
}
