// Implements the core cryptographic operations of the Pairwise POIDC protocol [1] in our setting.

// References
// [1] https://dl.acm.org/doi/10.1145/3320269.3384724

package ppoidc

import (
	RSA "OPPID/pkg/oppid/sign/rsa256"
	hash2 "OPPID/pkg/other/nizk/hash"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

const dstStr = "OPPID_BLS12384_XMD:SHA-256_PPOIDC_"

type PublicParams struct {
	rsa       *RSA.PublicParams
	hashProof *hash2.PublicParams
	pk        *hash2.ProvingKey
	vk        *hash2.VerifyingKey
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
type Nonce = [16]byte

type MaskedAud = []byte
type PairwiseSub = []byte
type MaskedSub = [hash2.MaxOutputLength]byte

type ClientIDBinding struct {
	Id   ClientId
	name ClientName
	ruri RedirectUri
	sig  RSA.Signature
}

type Request struct {
	maskedAud MaskedAud
	maskedSub MaskedSub
	proof     hash2.Proof
}

type UserRPState struct {
	rpNonce     Nonce
	uNonce1     Nonce
	uNonce2     Nonce
	PairwiseSub PairwiseSub
}

type PrivateIdToken struct {
	aud MaskedAud
	sub MaskedSub
	ctx []byte
	sid []byte
	sig RSA.Signature
}

func tokenBytes(maskedAud MaskedAud, maskedSub MaskedSub, ctx, sid []byte) []byte {
	tkBuf := bytes.NewBuffer(nil)
	tkBuf.Write([]byte(dstStr + "TOKEN"))
	tkBuf.Write(maskedAud)
	tkBuf.Write(maskedSub[:])
	tkBuf.Write(ctx)
	tkBuf.Write(sid)
	return tkBuf.Bytes()
}

func Setup() (*PublicParams, error) {
	hashProof, err := hash2.Setup()
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
	bin.Id = id[:]
	bin.name = name
	bin.ruri = ruri
	bin.sig = pp.rsa.Sign(k.rsaSk, buf.Bytes())

	return bin
}

// Init maps step (5) of the protocol [1, p.7]
func (pp *PublicParams) Init(ipk *PublicKey, uid UserId, cert ClientIDBinding, rpNonce Nonce) (Request, UserRPState, error) {
	var buf bytes.Buffer
	buf.Write([]byte(dstStr + "CERT"))
	buf.Write(cert.Id)
	buf.Write(cert.name)
	buf.Write(cert.ruri)

	isValid := pp.rsa.Verify(ipk.rsaPk, buf.Bytes(), cert.sig)
	if !isValid {
		return Request{}, UserRPState{}, errors.New("invalid certificate")
	}

	var uNonce1 Nonce
	_, _ = rand.Read(uNonce1[:])

	var uNonce2 Nonce
	_, _ = rand.Read(uNonce2[:])

	hash := sha256.New()
	hash.Write(cert.Id)
	hash.Write(rpNonce[:])
	hash.Write(uNonce1[:])
	maskedAud := hash.Sum(nil)

	circuitCidBytes, circuitNonce2Bytes, circuitUidBytes, circuitMaskedSub, err := hash2.BuildCircuitInputs(cert.Id, uNonce2[:], uid)
	if err != nil {
		return Request{}, UserRPState{}, err
	}

	hash.Reset()
	hash.Write(circuitUidBytes[:])
	hash.Write(circuitCidBytes[:])
	pairwiseSub := hash.Sum(nil)

	witness, err := pp.hashProof.NewWitness(circuitCidBytes, circuitNonce2Bytes, circuitUidBytes, circuitMaskedSub)
	if err != nil {
		return Request{}, UserRPState{}, err
	}

	proof, errP := pp.hashProof.Prove(witness, pp.pk)
	if errP != nil {
		return Request{}, UserRPState{}, errP
	}

	return Request{maskedAud, circuitMaskedSub, proof}, UserRPState{rpNonce, uNonce1, uNonce2, pairwiseSub}, nil
}

func (pp *PublicParams) Response(isk *PrivateKey, uid UserId, req Request, ctx, sid []byte) (PrivateIdToken, error) {
	var uidBytes [hash2.MaxInputLength]byte
	copy(uidBytes[:], uid)

	pubWitness, err := pp.hashProof.NewPublicWitness(uidBytes, req.maskedSub)
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

func (pp *PublicParams) Verify(ipk *PublicKey, id ClientId, st UserRPState, tk PrivateIdToken) bool {
	hash := sha256.New()
	hash.Write(id)
	hash.Write(st.rpNonce[:])
	hash.Write(st.uNonce1[:])
	maskedAud := hash.Sum(nil)

	var circuitNonce2Bytes [hash2.MaxInputLength]byte
	copy(circuitNonce2Bytes[:], st.uNonce2[:])

	hash.Reset()
	hash.Write(st.PairwiseSub)
	hash.Write(circuitNonce2Bytes[:])
	sum := hash.Sum(nil)

	var maskedSub MaskedSub
	copy(maskedSub[:], sum)

	tkBytes := tokenBytes(maskedAud, maskedSub, tk.ctx, tk.sid)
	return pp.rsa.Verify(ipk.rsaPk, tkBytes, tk.sig)
}
