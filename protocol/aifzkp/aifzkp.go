package aifzkp

import (
	PC "OPPID/internal/commit/pc"
	PS "OPPID/internal/sign/ps"
	"OPPID/internal/sign/rsa256"
)

type AIF struct {
	rsa *rsa256.RSA256
	ps  *PS.PS
	pc  *PC.PC
}

func New() *AIF {
	rsa := rsa256.New(2048)
	ps := PS.New("NEW_DST")
	pc := PC.New("NEW_DST")
	return &AIF{rsa, ps, pc}
}

func (a *AIF) Init()     {}
func (a *AIF) Request()  {}
func (a *AIF) Response() {}
func (a *AIF) Finalize() {}
func (a *AIF) Verify() bool {
	return true
}
