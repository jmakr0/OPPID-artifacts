package sig

import (
	PS "OPPID/internal/sign/ps"
	"testing"
)

func TestNewVerify(t *testing.T) {
	ps := PS.New("")
	msg := []byte("test")

	sig := ps.Sign(msg)

	p := &PublicInput{PSParams: ps}
	w := &Witness{msg: msg, sig: sig}

	pi := New(p, w)

	isValid := Verify(p, pi)
	if !isValid {
		t.Errorf("Verify(%v, %v) returned %v", p, pi, isValid)
	}
}
