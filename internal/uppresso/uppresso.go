// Implements the cryptographic operations of UPPRESSO [1] in our setting.
// Notations follow Table 3 from the paper (p.8).

// References:
// [1] https://arxiv.org/pdf/2110.10396

package uppresso

import (
	RSA "OPPID/pkg/sign/rsa256"
	"OPPID/pkg/utils"
	"bytes"
	"errors"
	GG "github.com/cloudflare/circl/ecc/bls12381"
)

const dstStr = "OPPID_BLS12384_XMD:SHA-256_UPPRESSO_"

type PublicParams struct {
	rsa *RSA.PublicParams
}

type PublicKey struct {
	rsaPk *RSA.PublicKey
}

type PrivateKey struct {
	rsaSk *RSA.PrivateKey
}

type IdRP = GG.G1
type EnPtRP = []byte // simulates fictional RP endpoint

type IdU = GG.Scalar

type PidRP = GG.G1
type PidU = GG.G1

type Acct = GG.G1 // corresponds to a ppid

// RP certificates from the paper do not include any key references
type CertRP struct {
	idRP   *IdRP
	enPtRP EnPtRP
	sig    RSA.Signature
}

type Token struct {
	pidU *PidU
	sig  RSA.Signature
}

// tokenBytes generates a byte representation of the token
func tokenBytes(pidRP *PidRP, pidU *PidU, ctx, sid []byte) []byte {
	tkBuf := bytes.NewBuffer(nil)
	tkBuf.Write([]byte(dstStr + "TOKEN"))
	tkBuf.Write(pidRP.Bytes())
	tkBuf.Write(pidU.Bytes())
	tkBuf.Write(ctx)
	tkBuf.Write(sid)
	return tkBuf.Bytes()
}

func Setup() *PublicParams {
	return &PublicParams{RSA.Setup(2048)}
}

func (pp *PublicParams) KeyGen() (*PrivateKey, *PublicKey) {
	rsaSk, rsaPk := pp.rsa.KeyGen()
	return &PrivateKey{rsaSk}, &PublicKey{rsaPk}
}

func (pp *PublicParams) Register(k *PrivateKey, id []byte, enPt EnPtRP) CertRP {
	r := utils.HashToScalar(id, []byte(dstStr))
	idRP := utils.GenerateG1Point(&r, GG.G1Generator())

	var buf bytes.Buffer
	buf.Write([]byte(dstStr + "CERT"))
	buf.Write(idRP.Bytes())
	buf.Write(enPt)

	return CertRP{idRP, enPt, pp.rsa.Sign(k.rsaSk, buf.Bytes())}
}

func (pp *PublicParams) Init(ipk *PublicKey, cert *CertRP) (*PidRP, *GG.Scalar, error) {
	var buf bytes.Buffer
	buf.Write([]byte(dstStr + "CERT"))
	buf.Write(cert.idRP.Bytes())
	buf.Write(cert.enPtRP)

	isValid := pp.rsa.Verify(ipk.rsaPk, buf.Bytes(), cert.sig)
	if !isValid {
		return nil, nil, errors.New("invalid certificate")
	}

	t := utils.GenerateRandomScalar()
	pidRP := utils.GenerateG1Point(t, cert.idRP)

	return pidRP, t, nil
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
