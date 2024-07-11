package com

import (
	PC "OPPID/pkg/commit/pc"
	"testing"
)

func TestNewVerify(t *testing.T) {
	pc := PC.Setup("")

	msg := []byte("test")
	commit, o := pc.Commit(msg)

	p := &PublicInput{params: pc, com: commit}
	w := &Witness{msg: msg, opening: o}

	pi := Prove(p, w)

	isValid := Verify(p, pi)
	if !isValid {
		t.Errorf("Verify(%v, %v) returned %v", p, pi, isValid)
	}
}
