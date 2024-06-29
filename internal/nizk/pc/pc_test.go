package pc

import (
	PC "OPPID/internal/commit/pedersen"
	"testing"
)

func TestNewVerify(t *testing.T) {
	pc, _ := PC.New()
	msg := []byte("test")

	commit, o, _ := pc.Commit(msg)

	p := &PublicInput{params: pc, com: commit}
	w := &Witness{msg: msg, opening: o}

	pi := New(p, w)

	isValid := Verify(pi, p)
	if !isValid {
		t.Errorf("Verify(%v, %v) returned %v", p, pi, isValid)
	}
}
