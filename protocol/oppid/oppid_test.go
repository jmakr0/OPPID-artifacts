package oppid

import (
<<<<<<< HEAD
	PC "OPPID/pkg/oppid/commit/pc"
	PS "OPPID/pkg/oppid/sign/ps"
	"OPPID/pkg/oppid/utils"
	NIZK "OPPID/pkg/other/nizk/comsig"
=======
	PC "OPPID/pkg/commit/pc"
	NIZK "OPPID/pkg/nizk/comsig"
	PS "OPPID/pkg/sign/ps"
	"OPPID/pkg/utils"
>>>>>>> main
	GG "github.com/cloudflare/circl/ecc/bls12381"
	"testing"
)

func setupAndKeyGen(t *testing.T) (*PublicParams, *PrivateKey, *PublicKey) {
	oppid := Setup()
	if oppid == nil {
		t.Fatalf("Setup returned nil")
	}
	if oppid.rsa == nil || oppid.pc == nil || oppid.ps == nil {
		t.Fatalf("Setup did not initialize all public parameters")
	}
	sk, pk := oppid.KeyGen()
	if sk == nil || pk == nil {
		t.Fatalf("KeyGen returned nil")
	}
	if sk.rsaSk == nil || sk.psSk == nil || sk.prfKey == nil {
		t.Fatalf("KeyGen did not initialize all private keys")
	}
	if pk.rsaPk == nil || pk.psPk == nil {
		t.Fatalf("KeyGen did not initialize all public keys")
	}
	return oppid, sk, pk
}

func TestKeyGen(t *testing.T) {
	setupAndKeyGen(t)
}

func TestRegister(t *testing.T) {
	oppid, sk, _ := setupAndKeyGen(t)
	rid := []byte("registrationID")
	cred := oppid.Register(sk, rid)
	if cred.sig == (PS.Signature{}) {
		t.Fatalf("Register did not return a valid signature")
	}
}

func TestInit(t *testing.T) {
	oppid, _, _ := setupAndKeyGen(t)
	rid := []byte("registrationID")
	orid, crid := oppid.Init(rid)
	if orid.opn == (PC.Opening{}) || orid.b == nil {
		t.Fatalf("Init did not return a valid UsrOpening")
	}
	if crid.com == (PC.Commitment{}) || crid.bx == nil {
		t.Fatalf("Init did not return a valid UsrCommitment")
	}
}

func TestRequest(t *testing.T) {
	oppid, sk, pk := setupAndKeyGen(t)
	rid := []byte("registrationID")
	cred := oppid.Register(sk, rid)
	orid, crid := oppid.Init(rid)
	sid := []byte("sessionID")
	auth, err := oppid.Request(pk, rid, cred, crid, orid, sid)
	if err != nil {
		t.Fatalf("Request returned an error: %v", err)
	}
	if auth.proof == (NIZK.Proof{}) {
		t.Fatalf("Request did not return a valid proof")
	}
}

func TestResponse(t *testing.T) {
	oppid, sk, pk := setupAndKeyGen(t)
	rid := []byte("registrationID")
	cred := oppid.Register(sk, rid)
	orid, crid := oppid.Init(rid)
	sid := []byte("sessionID")
	auth, err := oppid.Request(pk, rid, cred, crid, orid, sid)
	if err != nil {
		t.Fatalf("Request returned an error: %v", err)
	}
	uid := []byte("userID")
	ctx := []byte("context")
	token, err := oppid.Response(sk, auth, crid, uid, ctx, sid)
	if err != nil {
		t.Fatalf("Response returned an error: %v", err)
	}
	if token.sig == nil || token.by == nil {
		t.Fatalf("Response did not return a valid token")
	}
}

func TestFinalize(t *testing.T) {
	oppid, sk, pk := setupAndKeyGen(t)
	rid := []byte("registrationID")
	cred := oppid.Register(sk, rid)
	orid, crid := oppid.Init(rid)
	sid := []byte("sessionID")
	auth, err := oppid.Request(pk, rid, cred, crid, orid, sid)
	if err != nil {
		t.Fatalf("Request returned an error: %v", err)
	}
	uid := []byte("userID")
	ctx := []byte("context")
	token, err := oppid.Response(sk, auth, crid, uid, ctx, sid)
	if err != nil {
		t.Fatalf("Response returned an error: %v", err)
	}
	finalToken, ppid, err := oppid.Finalize(pk, rid, ctx, sid, crid, orid, token)
	if err != nil {
		t.Fatalf("Finalize returned an error: %v", err)
	}
	if finalToken.sig == nil || finalToken.by == nil || len(ppid) == 0 {
		t.Fatalf("Finalize did not return a valid finalized token")
	}
}

func TestVerify(t *testing.T) {
	oppid, sk, pk := setupAndKeyGen(t)
	rid := []byte("registrationID")
	cred := oppid.Register(sk, rid)
	orid, crid := oppid.Init(rid)
	sid := []byte("sessionID")
	auth, err := oppid.Request(pk, rid, cred, crid, orid, sid)
	if err != nil {
		t.Fatalf("Request returned an error: %v", err)
	}
	uid := []byte("userID")
	ctx := []byte("context")
	token, err := oppid.Response(sk, auth, crid, uid, ctx, sid)
	if err != nil {
		t.Fatalf("Response returned an error: %v", err)
	}
	finalToken, ppid, err := oppid.Finalize(pk, rid, ctx, sid, crid, orid, token)
	if err != nil {
		t.Fatalf("Finalize returned an error: %v", err)
	}
	isValid := oppid.Verify(pk, rid, ppid, ctx, sid, finalToken)
	if !isValid {
		t.Fatalf("Verify returned false for a valid finalized token")
	}
}

func TestInvalidUserCommitment(t *testing.T) {
	oppid, sk, pk := setupAndKeyGen(t)
	rid := []byte("registrationID")
	cred := oppid.Register(sk, rid)
	orid, crid := oppid.Init(rid)
	alteredCrid := UsrCommitment{com: crid.com, bx: utils.GenerateG1Point(utils.GenerateRandomScalar(), GG.G1Generator())}
	sid := []byte("sessionID")
	_, err := oppid.Request(pk, rid, cred, alteredCrid, orid, sid)
	if err == nil {
		t.Fatalf("Request accepted an altered user commitment")
	}
}

func TestInvalidTokenSignature(t *testing.T) {
	pp, sk, pk := setupAndKeyGen(t)
	rid := []byte("registrationID")
	cred := pp.Register(sk, rid)
	orid, crid := pp.Init(rid)
	sid := []byte("sessionID")
	auth, err := pp.Request(pk, rid, cred, crid, orid, sid)
	if err != nil {
		t.Fatalf("Request returned an error: %v", err)
	}
	uid := []byte("userID")
	ctx := []byte("context")
	token, err := pp.Response(sk, auth, crid, uid, ctx, sid)
	if err != nil {
		t.Fatalf("Response returned an error: %v", err)
	}
	token.sig[0] ^= 0xFF // Simulating an altered signature
	_, _, err = pp.Finalize(pk, rid, ctx, sid, crid, orid, token)
	if err == nil {
		t.Fatalf("Finalize accepted an altered token signature")
	}
}

func TestInvalidFinalizeCommitment(t *testing.T) {
	pp, sk, pk := setupAndKeyGen(t)
	rid := []byte("registrationID")
	cred := pp.Register(sk, rid)
	orid, crid := pp.Init(rid)
	sid := []byte("sessionID")
	auth, err := pp.Request(pk, rid, cred, crid, orid, sid)
	if err != nil {
		t.Fatalf("Request returned an error: %v", err)
	}
	uid := []byte("userID")
	ctx := []byte("context")
	token, err := pp.Response(sk, auth, crid, uid, ctx, sid)
	if err != nil {
		t.Fatalf("Response returned an error: %v", err)
	}
	alteredCrid := UsrCommitment{com: PC.Commitment{Element: GG.G1Generator()}, bx: crid.bx}
	_, _, err = pp.Finalize(pk, rid, ctx, sid, alteredCrid, orid, token)
	if err == nil {
		t.Fatalf("Finalize accepted an altered commitment")
	}
}

func TestInvalidVerifyCommitment(t *testing.T) {
	pp, sk, pk := setupAndKeyGen(t)
	rid := []byte("registrationID")
	cred := pp.Register(sk, rid)
	orid, crid := pp.Init(rid)
	sid := []byte("sessionID")
	auth, err := pp.Request(pk, rid, cred, crid, orid, sid)
	if err != nil {
		t.Fatalf("Request returned an error: %v", err)
	}
	uid := []byte("userID")
	ctx := []byte("context")
	token, err := pp.Response(sk, auth, crid, uid, ctx, sid)
	if err != nil {
		t.Fatalf("Response returned an error: %v", err)
	}
	finalToken, ppid, err := pp.Finalize(pk, rid, ctx, sid, crid, orid, token)
	if err != nil {
		t.Fatalf("Finalize returned an error: %v", err)
	}
	alteredFinalToken := finalToken
	alteredFinalToken.com = PC.Commitment{Element: GG.G1Generator()}
	isValid := pp.Verify(pk, rid, ppid, ctx, sid, alteredFinalToken)
	if isValid {
		t.Fatalf("Verify accepted an altered commitment")
	}
}

func TestInvalidVerifySignature(t *testing.T) {
	pp, sk, pk := setupAndKeyGen(t)
	rid := []byte("registrationID")
	cred := pp.Register(sk, rid)
	orid, crid := pp.Init(rid)
	sid := []byte("sessionID")
	auth, err := pp.Request(pk, rid, cred, crid, orid, sid)
	if err != nil {
		t.Fatalf("Request returned an error: %v", err)
	}
	uid := []byte("userID")
	ctx := []byte("context")
	token, err := pp.Response(sk, auth, crid, uid, ctx, sid)
	if err != nil {
		t.Fatalf("Response returned an error: %v", err)
	}
	finalToken, ppid, err := pp.Finalize(pk, rid, ctx, sid, crid, orid, token)
	if err != nil {
		t.Fatalf("Finalize returned an error: %v", err)
	}
	alteredFinalToken := finalToken
	alteredFinalToken.sig[0] ^= 0xFF // Simulating an altered signature
	isValid := pp.Verify(pk, rid, ppid, ctx, sid, alteredFinalToken)
	if isValid {
		t.Fatalf("Verify accepted an altered signature")
	}
}
