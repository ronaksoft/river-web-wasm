package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	river_conn "git.ronaksoft.com/river/web-wasm/connection"
	"git.ronaksoft.com/river/web-wasm/msg"
	"git.ronaksoft.com/river/web-wasm/utils"
	"github.com/monnand/dhkx"
	"math/big"
	"syscall/js"
)

var (
	SK river_conn.ServerKeys
)

func main() {
	done := make(chan struct{}, 0)
	global := js.Global()
	global.Set("wasmAuthStep1", js.FuncOf(authStep1))
	global.Set("wasmAuthStep2", js.FuncOf(authStep2))
	<-done
}

func authStep1(this js.Value, args []js.Value) interface{} {
	req := msg.InitConnect{
		ClientNonce: utils.RandomUint64(),
	}
	bytes, _ := req.Marshal()
	return bytes
}

func authStep2(this js.Value, args []js.Value) interface{} {
	enc, err := base64.StdEncoding.DecodeString(args[0].String())
	if err != nil {
		return err.Error()
	}

	x := msg.InitResponse{}
	err = x.Unmarshal(enc)
	if err != nil {
		return err.Error()
	}

	req := msg.InitCompleteAuth{
		ClientNonce:      x.ClientNonce,
		ServerNonce:      x.ServerNonce,
		ClientDHPubKey:   nil,
		P:                0,
		Q:                0,
		EncryptedPayload: nil,
	}

	// Generate DH Pub Key
	dhGroup, err := SK.GetDhGroup(int64(x.DHGroupFingerPrint))
	if err != nil {
		return err.Error()
	}

	dhPrime := big.NewInt(0)
	dhPrime.SetString(dhGroup.Prime, 16)

	// 30

	dh := dhkx.CreateGroup(dhPrime, big.NewInt(int64(dhGroup.Gen)))
	clientDhKey, err := dh.GeneratePrivateKey(rand.Reader)
	if err != nil {
		return err.Error()
	}

	req.ClientDHPubKey = clientDhKey.Bytes()

	// 45
	p, q := utils.SplitPQ(big.NewInt(int64(x.PQ)))
	if p.Cmp(q) < 0 {
		req.P = p.Uint64()
		req.Q = q.Uint64()
	} else {
		req.P = q.Uint64()
		req.Q = p.Uint64()
	}

	// 55
	q2Internal := msg.InitCompleteAuthInternal{}
	q2Internal.SecretNonce = []byte(utils.RandomID(16))

	// 60
	serverPubKey, err := SK.GetPublicKey(int64(x.RSAPubKeyFingerPrint))
	if err != nil {
		return err.Error()
	}

	n := big.NewInt(0)
	n.SetString(serverPubKey.N, 10)
	rsaPublicKey := rsa.PublicKey{
		N: n,
		E: int(serverPubKey.E),
	}

	// 65
	decrypted, err := q2Internal.Marshal()
	if err != nil {
		return err.Error()
	}

	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, &rsaPublicKey, decrypted)
	if err != nil {
		return err.Error()
	}

	// 70
	req.EncryptedPayload = encrypted

	bytes, _ := req.Marshal()
	return bytes
}
