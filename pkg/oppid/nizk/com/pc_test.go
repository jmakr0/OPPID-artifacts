package com

import (
	PC "OPPID-artifacts/pkg/oppid/commit/pc"
	"testing"
)

func TestProveVerify(t *testing.T) {
	pc := PC.Setup(nil)

	msg := []byte("test")
	com, opn := pc.Commit(msg)

	p := &PublicInput{pc, &com}
	w := &Witness{msg, &opn}

	pi := Prove(p, w)

	isValid := Verify(p, pi)
	if !isValid {
		t.Errorf("Verify(%v, %v) returned %v", p, pi, isValid)
	}
}
