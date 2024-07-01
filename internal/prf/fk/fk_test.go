package fk

import "testing"

func TestFK_Eval(t *testing.T) {
	fk := New()

	msg := []byte("Inner test message")
	k := []byte("Outer test message")

	y := fk.Eval(msg, k)
	if y.IsIdentity() || !y.IsOnG1() {
		t.Fatalf("HmacPRF output is invalid")
	}
}
