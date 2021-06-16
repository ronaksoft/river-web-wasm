package river_conn

import (
	"encoding/base64"
	_errors "git.ronaksoft.com/river/web-wasm/errors"
	"git.ronaksoft.com/river/web-wasm/msg"
	"syscall/js"
	"time"
)

type ServerKeys struct {
	msg.ServerKeys
}

// getPublicKey
func (v *ServerKeys) GetPublicKey(keyFP int64) (*msg.PublicKey, error) {
	for _, pk := range v.PublicKeys {
		if pk.FingerPrint == keyFP {
			return pk, nil
		}
	}
	return nil, _errors.ErrNotFound
}

// getDhGroup
func (v *ServerKeys) GetDhGroup(keyFP int64) (*msg.DHGroup, error) {
	for _, dh := range v.DHGroups {
		if dh.FingerPrint == keyFP {
			return dh, nil
		}
	}
	return nil, _errors.ErrNotFound
}

type RiverConnection struct {
	msg.RiverConnection
}

// NewRiverConnection
func NewRiverConnection(connInfo string) (rc *RiverConnection, err error) {
	rc = new(RiverConnection)
	err = rc.Load(connInfo)
	if err != nil {
		return
	}

	rc.DiffTime = 0
	return
}

// Save
func (v *RiverConnection) Save() {
	if bytes, err := v.Marshal(); err != nil {
		//fmt.Println(err.Error(), "RiverConnection::Save")
	} else {
		//fmt.Println(bytes)
		js.Global().Call("jsSave", base64.StdEncoding.EncodeToString(bytes))
	}
}

// Load
func (v *RiverConnection) Load(connInfo string) error {
	connInfoByte, err := base64.StdEncoding.DecodeString(connInfo)
	if err != nil {
		return err
	}
	if err := v.Unmarshal(connInfoByte); err != nil {
		//fmt.Println(err.Error(), "RiverConnection::Load")
		return err
	}
	return nil
}

func (v *RiverConnection) SetServerTime(timestamp int64) {
	v.DiffTime = timestamp - time.Now().Unix()
}

func (v *RiverConnection) Now() int64 {
	return time.Now().Unix() + v.DiffTime
}
