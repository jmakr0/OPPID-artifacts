package fk

import "testing"

func TestFK_Eval(t *testing.T) {
	fk := New()

	innerMsg := []byte("Inner test message")
	outerMsg := []byte("Outer test message")

	y := fk.Eval(innerMsg, outerMsg)
	if y.IsIdentity() || !y.IsOnG1() {
		t.Fatalf("PRF output is invalid")
	}
}
