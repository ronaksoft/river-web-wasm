package river

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	river_conn "git.ronaksoft.com/river/web-wasm/connection"
	_errors "git.ronaksoft.com/river/web-wasm/errors"
	"git.ronaksoft.com/river/web-wasm/msg"
	"git.ronaksoft.com/river/web-wasm/utils"
	"github.com/monnand/dhkx"
	"math/big"
)

type Callback func(time int64)

type River struct {
	ConnInfo     *river_conn.RiverConnection
	authID       int64
	authKey      []byte
	messageSeq   int64
	serverKeys   river_conn.ServerKeys
	dh           *dhkx.DHGroup
	clientDhKey  *dhkx.DHKey
	internalAuth *msg.InitCompleteAuthInternal
}

func (r *River) Load(connInfo, serverKeys string) (err error) {
	serverKeysByte, err := base64.StdEncoding.DecodeString(serverKeys)
	if err != nil {
		return
	}

	err = r.serverKeys.Unmarshal(serverKeysByte)
	if err != nil {
		return
	}

	r.ConnInfo, err = river_conn.NewRiverConnection(connInfo)
	if err != nil {
		return _errors.ErrNoAuthKey
	}

	if r.ConnInfo.AuthID == 0 {
		return _errors.ErrNoAuthKey
	}

	r.authID = r.ConnInfo.AuthID
	r.authKey = r.ConnInfo.AuthKey[:]
	return
}

func (r *River) AuthStep1(cb Callback) []byte {
	/* Start Progress */
	cb(0)
	/* End progress */
	req := msg.InitConnect{
		ClientNonce: utils.RandomUint64(),
	}
	bytes, _ := req.Marshal()
	/* Start Progress */
	cb(5)
	/* End progress */
	return bytes
}

func (r *River) AuthStep2(in []byte, cb Callback) (bytes []byte, err error) {
	/* Start Progress */
	cb(12)
	/* End progress */
	x := msg.InitResponse{}
	err = x.Unmarshal(in)
	if err != nil {
		return
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
	dhGroup, err := r.serverKeys.GetDhGroup(int64(x.DHGroupFingerPrint))
	if err != nil {
		return
	}

	/* Start Progress */
	cb(17)
	/* End progress */

	dhPrime := big.NewInt(0)
	dhPrime.SetString(dhGroup.Prime, 16)

	/* Start Progress */
	cb(30)
	/* End progress */

	r.dh = dhkx.CreateGroup(dhPrime, big.NewInt(int64(dhGroup.Gen)))
	r.clientDhKey, err = r.dh.GeneratePrivateKey(rand.Reader)
	if err != nil {
		return
	}

	req.ClientDHPubKey = r.clientDhKey.Bytes()

	/* Start Progress */
	cb(35)
	/* End progress */
	p, q := utils.SplitPQ(big.NewInt(int64(x.PQ)))
	if p.Cmp(q) < 0 {
		req.P = p.Uint64()
		req.Q = q.Uint64()
	} else {
		req.P = q.Uint64()
		req.Q = p.Uint64()
	}

	/* Start Progress */
	cb(45)
	/* End progress */
	r.internalAuth = &msg.InitCompleteAuthInternal{}
	r.internalAuth.SecretNonce = []byte(utils.RandomID(16))

	/* Start Progress */
	cb(50)
	/* End progress */
	serverPubKey, err := r.serverKeys.GetPublicKey(int64(x.RSAPubKeyFingerPrint))
	if err != nil {
		return
	}

	n := big.NewInt(0)
	n.SetString(serverPubKey.N, 10)
	rsaPublicKey := rsa.PublicKey{
		N: n,
		E: int(serverPubKey.E),
	}

	/* Start Progress */
	cb(55)
	/* End progress */
	decrypted, err := r.internalAuth.Marshal()
	if err != nil {
		return
	}

	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, &rsaPublicKey, decrypted)
	if err != nil {
		return
	}

	/* Start Progress */
	cb(60)
	/* End progress */
	req.EncryptedPayload = encrypted

	bytes, err = req.Marshal()
	return
}

func (r *River) AuthStep3(in []byte, cb Callback) (bytes []byte, err error) {
	x := msg.InitAuthCompleted{}
	err = x.Unmarshal(in)
	if err != nil {
		return
	}

	switch x.Status {
	case msg.InitAuthCompleted_OK:
		var (
			serverDhKey *dhkx.DHKey
			authKeyHash []byte
			secretHash  []byte
		)

		serverDhKey, err = r.dh.ComputeKey(dhkx.NewPublicKey(x.ServerDHPubKey), r.clientDhKey)
		if err != nil {
			return
		}

		/* Start Progress */
		cb(70)
		/* End progress */

		copy(r.ConnInfo.AuthKey[:], serverDhKey.Bytes())
		authKeyHash, err = utils.Sha256(r.ConnInfo.AuthKey[:])
		if err != nil {
			return
		}

		r.ConnInfo.AuthID = int64(binary.LittleEndian.Uint64(authKeyHash[24:32]))

		/* Start Progress */
		cb(80)
		/* End progress */

		var secret []byte
		secret = append(secret, r.internalAuth.SecretNonce...)
		secret = append(secret, byte(msg.InitAuthCompleted_OK))
		secret = append(secret, authKeyHash[:8]...)
		secretHash, err = utils.Sha256(secret)
		if err != nil {
			return
		}

		if x.SecretHash != binary.LittleEndian.Uint64(secretHash[24:32]) {
			//fmt.Println(x.SecretHash, binary.LittleEndian.Uint64(secretHash[24:32]))
			err = _errors.ErrSecretNonceMismatch
			return
		}

		/* Start Progress */
		cb(90)
		/* End progress */

		r.ConnInfo.Save()
		r.authKey = r.ConnInfo.AuthKey[:]
		r.authID = r.ConnInfo.AuthID

		/* Start Progress */
		cb(100)
		/* End progress */

	case msg.InitAuthCompleted_RETRY:
		// TODO:: Retry with new DHKey
	case msg.InitAuthCompleted_FAIL:
		err = _errors.ErrAuthFailed
		return
	}
	return
}

func (r *River) Decode(in []byte) (out *msg.MessageEnvelope, err error) {
	res := msg.ProtoMessage{}
	err = res.Unmarshal(in)
	if err != nil {
		return
	}

	if res.AuthID == 0 {
		out = new(msg.MessageEnvelope)
		err = out.Unmarshal(res.Payload)
		if err != nil {
			return
		}

		return
	}

	decryptedBytes, err := utils.Decrypt(r.authKey, res.MessageKey, res.Payload)
	if err != nil {
		//js.Global().Call("fnDecryptError")
		return
	}

	receivedEncryptedPayload := new(msg.ProtoEncryptedPayload)
	err = receivedEncryptedPayload.Unmarshal(decryptedBytes)
	if err != nil {
		return
	}

	out = receivedEncryptedPayload.Envelope
	return
}

func (r *River) Encode(in *msg.MessageEnvelope) (bytes []byte, err error) {
	protoMessage := new(msg.ProtoMessage)
	protoMessage.AuthID = r.authID
	protoMessage.MessageKey = make([]byte, 32)

	if r.authID == 0 || in.Constructor == msg.C_SystemGetServerTime ||
		in.Constructor == msg.C_SystemGetInfo || in.Constructor == msg.C_SystemGetSalts ||
		in.Constructor == msg.C_InitConnect || in.Constructor == msg.C_InitCompleteAuth {
		protoMessage.AuthID = 0
		protoMessage.Payload, err = in.Marshal()
		if err != nil {
			return
		}
	} else {
		var unencryptedBytes []byte

		protoMessage.AuthID = r.authID
		r.messageSeq++
		encryptedPayload := msg.ProtoEncryptedPayload{
			ServerSalt: 234242, // TODO:: ServerSalt ?
			Envelope:   in,
		}
		encryptedPayload.MessageID = uint64(r.ConnInfo.Now()<<32 | r.messageSeq)
		unencryptedBytes, err = encryptedPayload.Marshal()
		if err != nil {
			return
		}

		encryptedPayloadBytes, _ := utils.Encrypt(r.authKey, unencryptedBytes)
		messageKey := utils.GenerateMessageKey(r.authKey, unencryptedBytes)
		copy(protoMessage.MessageKey, messageKey)
		protoMessage.Payload = encryptedPayloadBytes
	}

	bytes, err = protoMessage.Marshal()
	if err != nil {
		return
	}

	return
}

// GenSrpHash generates a hash to be used in AuthCheckPassword and other related apis
func (r *River) GenSrpHash(password []byte, algorithm int64, algorithmData []byte) (bytes []byte, err error) {
	switch algorithm {
	case msg.C_PasswordAlgorithmVer6A:
		algo := &msg.PasswordAlgorithmVer6A{}
		err = algo.Unmarshal(algorithmData)

		if err != nil {
			return
		}

		p := big.NewInt(0).SetBytes(algo.P)
		x := big.NewInt(0).SetBytes(utils.PH2(password, algo.Salt1, algo.Salt2))
		v := big.NewInt(0).Exp(big.NewInt(int64(algo.G)), x, p)
		bytes = v.Bytes()
		return
	default:
		return
	}
}

// GenInputPassword  accepts AccountPassword marshaled as argument and return InputPassword marshaled
func (r *River) GenInputPassword(password []byte, accountPasswordBytes []byte) (bytes []byte, err error) {
	ap := &msg.AccountPassword{}
	err = ap.Unmarshal(accountPasswordBytes)

	algo := &msg.PasswordAlgorithmVer6A{}
	err = algo.Unmarshal(ap.AlgorithmData)
	if err != nil {
		return
	}

	p := big.NewInt(0).SetBytes(algo.P)
	g := big.NewInt(0).SetInt64(int64(algo.G))
	k := big.NewInt(0).SetBytes(utils.K(p, g))

	x := big.NewInt(0).SetBytes(utils.PH2(password, algo.Salt1, algo.Salt2))
	v := big.NewInt(0).Exp(g, x, p)
	a := big.NewInt(0).SetBytes(ap.RandomData)
	ga := big.NewInt(0).Exp(g, a, p)
	gb := big.NewInt(0).SetBytes(ap.SrpB)
	u := big.NewInt(0).SetBytes(utils.U(ga, gb))
	kv := big.NewInt(0).Mod(big.NewInt(0).Mul(k, v), p)
	t := big.NewInt(0).Mod(big.NewInt(0).Sub(gb, kv), p)
	if t.Sign() < 0 {
		t.Add(t, p)
	}
	sa := big.NewInt(0).Exp(t, big.NewInt(0).Add(a, big.NewInt(0).Mul(u, x)), p)
	m1 := utils.M(p, g, algo.Salt1, algo.Salt2, ga, gb, sa)

	inputPassword := &msg.InputPassword{
		SrpID: ap.SrpID,
		A:     utils.Pad(ga),
		M1:    m1,
	}

	bytes, err = inputPassword.Marshal()
	if err != nil {
		return
	}

	return
}

func TeamHeader(teamID, teamAccessHash string) []*msg.KeyValue {
	if teamID == "0" {
		return nil
	}

	kv := make([]*msg.KeyValue, 0, 2)
	kv = append(kv,
		&msg.KeyValue{
			Key:   "TeamID",
			Value: teamID,
		},
		&msg.KeyValue{
			Key:   "TeamAccess",
			Value: teamAccessHash,
		},
	)
	return kv
}
