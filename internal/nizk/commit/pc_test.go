package commit

import (
	PC "OPPID/internal/commit/pc"
	"testing"
)

func TestNewVerify(t *testing.T) {
	pc, _ := PC.New()
	msg := []byte("test")

	commit, o, _ := pc.Commit(msg)

	p := &PublicInput{params: pc, com: commit}
	w := &Witness{msg: msg, opening: o}

	pi := New(p, w)

	isValid := Verify(p, pi)
	if !isValid {
		t.Errorf("Verify(%v, %v) returned %v", p, pi, isValid)
	}
}
