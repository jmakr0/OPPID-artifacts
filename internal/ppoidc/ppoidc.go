// Implements the core cryptographic operations of the Pairwise POIDC protocol [1].

// References
// [1] https://dl.acm.org/doi/10.1145/3320269.3384724

package ppoidc

import (
	NIZK "OPPID/pkg/nizk/hash"
	RSA "OPPID/pkg/sign/rsa256"
	"OPPID/pkg/utils"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	GG "github.com/cloudflare/circl/ecc/bls12381"
)

const dstStr = "OPPID_BLS12384_XMD:SHA-256_PP-OIDC_"

type PublicParams struct {
	rsa      *RSA.PublicParams
	proofSys *NIZK.PublicParams
}

type PublicKey struct {
	rsaPk *RSA.PublicKey
}

type PrivateKey struct {
	rsaSk *RSA.PrivateKey
}

type UserId = []byte

type ClientId = []byte
type ClientName = []byte
type RedirectUri = []byte
type Nonce = []byte

type MaskedAud = []byte
type PairwiseSub = []byte
type MaskedSub = []byte

type ClientIDBinding struct {
	id   ClientId
	name ClientName
	ruri RedirectUri
	sig  RSA.Signature
}

type Token struct {
	pidU []byte
	sig  RSA.Signature
}

//// tokenBytes generates a byte representation of the token
//func tokenBytes(pidRP *PidRP, pidU *PidU, ctx, sid []byte) []byte {
//	tkBuf := bytes.NewBuffer(nil)
//	tkBuf.Write([]byte(dstStr + "TOKEN"))
//	tkBuf.Write(pidRP.Bytes())
//	tkBuf.Write(pidU.Bytes())
//	tkBuf.Write(ctx)
//	tkBuf.Write(sid)
//	return tkBuf.Bytes()
//}

func Setup() (*PublicParams, error) {
	proofSys, err := NIZK.Setup()
	if err != nil {
		return nil, err
	}
	return &PublicParams{RSA.Setup(2048), proofSys}, nil
}

func (pp *PublicParams) KeyGen() (*PrivateKey, *PublicKey) {
	rsaSk, rsaPk := pp.rsa.KeyGen()
	return &PrivateKey{rsaSk}, &PublicKey{rsaPk}
}

func (pp *PublicParams) Register(k *PrivateKey, name ClientName, ruri RedirectUri) ClientIDBinding {
	var id [16]byte
	_, _ = rand.Read(id[:])

	var buf bytes.Buffer
	buf.Write([]byte(dstStr + "CERT"))
	buf.Write(id[:])
	buf.Write(name)
	buf.Write(ruri)

	var bin ClientIDBinding
	bin.id = id[:]
	bin.name = name
	bin.ruri = ruri
	bin.sig = pp.rsa.Sign(k.rsaSk, buf.Bytes())

	return bin
}

// Init maps step (5) of the protocol [1, p.7]
func (pp *PublicParams) Init(ipk *PublicKey, uid UserId, cert *ClientIDBinding, nonceRP Nonce) (*PidRP, *GG.Scalar, error) {
	var buf bytes.Buffer
	buf.Write([]byte(dstStr + "CERT"))
	buf.Write(cert.id)
	buf.Write(cert.name)
	buf.Write(cert.ruri)

	isValid := pp.rsa.Verify(ipk.rsaPk, buf.Bytes(), cert.sig)
	if !isValid {
		return nil, nil, errors.New("invalid certificate")
	}

	var nonceUser1 [16]byte
	_, _ = rand.Read(nonceUser1[:])

	var nonceUser2 [16]byte
	_, _ = rand.Read(nonceUser2[:])

	hash := sha256.New()
	hash.Write(cert.id)
	hash.Write(nonceRP)
	hash.Write(nonceUser1[:])
	maskedAud := hash.Sum(nil)

	hash.Reset()
	hash.Write(uid)
	hash.Write(cert.id)
	pairwiseSub := hash.Sum(nil)

	hash.Reset()
	hash.Write(pairwiseSub)
	hash.Write(nonceUser2[:])
	maskedSub := hash.Sum(nil)

	witness := pp.proofSys.NewWitness()

	return
}

func (pp *PublicParams) Request(idRP *IdRP, t *GG.Scalar) *PidRP {
	return utils.GenerateG1Point(t, idRP)
}

func (pp *PublicParams) Response(isk *PrivateKey, pidRP *PidRP, uid *IdU, ctx, sid []byte) Token {
	pidU := utils.GenerateG1Point(uid, pidRP)
	tkBytes := tokenBytes(pidRP, pidU, ctx, sid)
	sig := pp.rsa.Sign(isk.rsaSk, tkBytes)

	return Token{pidU, sig}
}

func (pp *PublicParams) Verify(ipk *PublicKey, pidRP *PidRP, t *GG.Scalar, ctx, sid []byte, tk Token) *Acct {
	tkBytes := tokenBytes(pidRP, tk.pidU, ctx, sid)
	if !pp.rsa.Verify(ipk.rsaPk, tkBytes, tk.sig) {
		return nil
	}

	tInv := new(GG.Scalar)
	tInv.Inv(t)

	return utils.GenerateG1Point(t, tk.pidU)
}
