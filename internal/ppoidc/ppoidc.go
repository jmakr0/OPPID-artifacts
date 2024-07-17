// Implements the core cryptographic operations of the Pairwise POIDC protocol [1].

// References
// [1] https://dl.acm.org/doi/10.1145/3320269.3384724

package ppoidc

import (
	NIZK "OPPID/pkg/nizk/hash"
	RSA "OPPID/pkg/sign/rsa256"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

const dstStr = "OPPID_BLS12384_XMD:SHA-256_PPOIDC_"

type PublicParams struct {
	rsa       *RSA.PublicParams
	hashProof *NIZK.PublicParams
	pk        *NIZK.ProvingKey
	vk        *NIZK.VerifyingKey
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

type Request struct {
	maskedAud MaskedAud
	maskedSub MaskedSub
	proof     NIZK.Proof
}

type UserRPState struct {
	nonce1      Nonce
	nonce2      Nonce
	PairwiseSub PairwiseSub
}

type PrivateIdToken struct {
	aud MaskedAud
	sub MaskedSub
	ctx []byte
	sid []byte
	sig RSA.Signature
}

// tokenBytes generates a byte representation of the token
func tokenBytes(maskedAud MaskedAud, maskedSub MaskedSub, ctx, sid []byte) []byte {
	tkBuf := bytes.NewBuffer(nil)
	tkBuf.Write([]byte(dstStr + "TOKEN"))
	tkBuf.Write(maskedAud)
	tkBuf.Write(maskedSub)
	tkBuf.Write(ctx)
	tkBuf.Write(sid)
	return tkBuf.Bytes()
}

func Setup() (*PublicParams, error) {
	hashProof, err := NIZK.Setup()
	if err != nil {
		return nil, err
	}
	pk, vk, errKGen := hashProof.KeyGen()
	if errKGen != nil {
		panic(errKGen)
	}
	return &PublicParams{RSA.Setup(2048), hashProof, pk, vk}, nil
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
func (pp *PublicParams) Init(ipk *PublicKey, uid UserId, cert ClientIDBinding, nonceRP Nonce) (Request, UserRPState, error) {
	var buf bytes.Buffer
	buf.Write([]byte(dstStr + "CERT"))
	buf.Write(cert.id)
	buf.Write(cert.name)
	buf.Write(cert.ruri)

	isValid := pp.rsa.Verify(ipk.rsaPk, buf.Bytes(), cert.sig)
	if !isValid {
		return Request{}, UserRPState{}, errors.New("invalid certificate")
	}

	var nonce1 [16]byte
	_, _ = rand.Read(nonce1[:])

	var nonce2 [16]byte
	_, _ = rand.Read(nonce2[:])

	hash := sha256.New()
	hash.Write(cert.id)
	hash.Write(nonceRP)
	hash.Write(nonce1[:])
	maskedAud := hash.Sum(nil)

	NIZK.BuildCircuitInputs()

	// Need to pad arrays due to the hash that will be proven via the circuit
	var uidBytes [NIZK.MaxInputLength]byte
	copy(uidBytes[:], uid)

	var cidBytes [NIZK.MaxInputLength]byte
	copy(cidBytes[:], cert.id)

	hash.Reset()
	hash.Write(uidBytes[:])
	hash.Write(cidBytes[:])
	pairwiseSub := hash.Sum(nil)

	var nonce2Bytes [NIZK.MaxInputLength]byte
	copy(nonce2Bytes[:], nonce2[:])

	hash.Reset()
	hash.Write(pairwiseSub)
	hash.Write(nonce2Bytes[:])
	maskedSub := hash.Sum(nil)

	witness, err := pp.hashProof.NewWitness(cert.id, nonce2[:], uid)
	if err != nil {
		return Request{}, UserRPState{}, err
	}

	proof, errP := pp.hashProof.Prove(witness, pp.pk)
	if errP != nil {
		return Request{}, UserRPState{}, errP
	}

	return Request{maskedAud, maskedSub, proof}, UserRPState{nonce1[:], nonce2[:], pairwiseSub}, nil
}

func (pp *PublicParams) Response(isk *PrivateKey, uid UserId, req Request, ctx, sid []byte) (PrivateIdToken, error) {
	pubWitness, err := pp.hashProof.NewPublicWitness(uid)
	if err != nil {
		return PrivateIdToken{}, err
	}
	if !pp.hashProof.Verify(req.proof, pubWitness, pp.vk) {
		return PrivateIdToken{}, errors.New("invalid proof")
	}
	tkBytes := tokenBytes(req.maskedAud, req.maskedSub, ctx, sid)
	sig := pp.rsa.Sign(isk.rsaSk, tkBytes)

	return PrivateIdToken{req.maskedAud, req.maskedSub, ctx, sid, sig}, nil
}

func (pp *PublicParams) Verify(ipk *PublicKey, id ClientId, nonceRP Nonce, nonceUsr1 Nonce, nonceUsr2 Nonce, pairwiseSub PairwiseSub, tk PrivateIdToken) bool {
	hash := sha256.New()
	hash.Write(id)
	hash.Write(nonceRP)
	hash.Write(nonceUsr1)
	maskedAud := hash.Sum(nil)

	hash.Reset()
	hash.Write(pairwiseSub)
	hash.Write(nonceUsr2)
	maskedSub := hash.Sum(nil)

	tkBytes := tokenBytes(maskedAud, maskedSub, tk.ctx, tk.sid)
	return pp.rsa.Verify(ipk.rsaPk, tkBytes, tk.sig)
}
