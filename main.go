package main

import (
	"encoding/base64"
	"git.ronaksoft.com/river/web-wasm/msg"
	"git.ronaksoft.com/river/web-wasm/river"
	"math/rand"
	"syscall/js"
	"time"
)

var (
	_river *river.River
)

func main() {
	rand.Seed(time.Now().UnixNano())
	_river = new(river.River)

	done := make(chan struct{}, 0)

	global := js.Global()
	global.Set("wasmLoad", js.FuncOf(load))
	global.Set("wasmSessionInc", js.FuncOf(sessionInc))
	global.Set("wasmSetServerTime", js.FuncOf(setServerTime))
	global.Set("wasmAuth", js.FuncOf(auth))
	global.Set("wasmDecode", js.FuncOf(decode))
	global.Set("wasmEncode", js.FuncOf(encode))
	global.Set("wasmGenSrpHash", js.FuncOf(generateSrpHash))
	global.Set("wasmGenInputPassword", js.FuncOf(generateInputPassword))

	js.Global().Call("jsLoaded", nil)
	<-done

	//fmt.Println("Bye Wasm !")
}

func load(this js.Value, args []js.Value) interface{} {
	connInfo := args[0].String()
	serverPubKeys := args[1].String()
	err := _river.Load(connInfo, serverPubKeys)
	if err != nil {
		return err.Error()
	}

	return nil
}

func sessionInc(this js.Value, args []js.Value) interface{} {
	_river.SessionInc()
	return nil
}

func setServerTime(this js.Value, args []js.Value) interface{} {
	serverTime := int64(args[0].Float())
	_river.ConnInfo.SetServerTime(serverTime)
	return nil
}

func auth(this js.Value, inps []js.Value) interface{} {
	//go func(inps []js.Value) {
	id := int64(inps[0].Float())
	step := int64(inps[1].Float())
	var (
		bytes []byte
		err   error
		enc   []byte
	)
	switch step {
	case 1:
		bytes = _river.AuthStep1(dispatchProgress)
	case 2:
		enc, err = base64.StdEncoding.DecodeString(inps[2].String())
		if err != nil {
			return nil
		}

		bytes, err = _river.AuthStep2(enc, dispatchProgress)
		if err != nil {
			return nil
		}
	case 3:
		enc, err = base64.StdEncoding.DecodeString(inps[2].String())
		if err != nil {
			return nil
		}

		bytes, err = _river.AuthStep3(enc, dispatchProgress)
		if err != nil {
			//fmt.Println(err)
			return nil
		}
	}

	js.Global().Call("jsAuth", id, step, base64.StdEncoding.EncodeToString(bytes))
	//}(args)
	return nil
}

func decode(this js.Value, inps []js.Value) interface{} {
	//go func(inps []js.Value) {
	withParse := inps[0].Bool()

	enc, err := base64.StdEncoding.DecodeString(inps[1].String())
	if err != nil {
		return nil
	}

	env, err := _river.Decode(enc)
	if err != nil || env == nil {
		return nil
	}

	reqId := int64(inps[2].Float())

	if withParse {
		parseEnvelope(env)
	} else {
		if reqId != 0 {
			env.RequestID = uint64(reqId)
		}
		js.Global().Call("jsDecode", false, env.RequestID, env.Constructor, base64.StdEncoding.EncodeToString(env.Message))
	}
	//}(args)

	return nil
}

func encode(this js.Value, inps []js.Value) interface{} {
	//go func(inps []js.Value) {
	withSend := inps[0].Bool()

	env := new(msg.MessageEnvelope)

	env.RequestID = uint64(inps[1].Float())
	env.Constructor = int64(inps[2].Float())
	enc, err := base64.StdEncoding.DecodeString(inps[3].String())
	if err != nil {
		return nil
	}
	env.Message = enc

	if len(inps) > 4 {
		teamId := inps[4].String()
		teamAccessHash := inps[5].String()
		if teamId != "0" && teamAccessHash != "0" {
			env.Header = river.TeamHeader(teamId, teamAccessHash)
		}
	}

	bytes, err := _river.Encode(env)
	if err != nil {
		return nil
	}

	js.Global().Call("jsEncode", withSend, env.RequestID, base64.StdEncoding.EncodeToString(bytes))
	//}(args)

	return nil
}

func generateSrpHash(this js.Value, inps []js.Value) interface{} {
	//go func(inps []js.Value) {
	id := int64(inps[0].Float())
	pass, err := base64.StdEncoding.DecodeString(inps[1].String())
	if err != nil {
		return nil
	}

	algorithm := int64(inps[2].Float())
	algorithmData, err := base64.StdEncoding.DecodeString(inps[3].String())
	if err != nil {
		return nil
	}

	res, err := _river.GenSrpHash(pass, int64(algorithm), algorithmData)
	if err != nil {
		return nil
	}

	js.Global().Call("jsGenSrpHash", id, base64.StdEncoding.EncodeToString(res))
	//}(args)
	return nil
}

func generateInputPassword(this js.Value, inps []js.Value) interface{} {
	//go func(inps []js.Value) {
	id := int64(inps[0].Float())
	pass, err := base64.StdEncoding.DecodeString(inps[1].String())
	if err != nil {
		return nil
	}

	accountPass, err := base64.StdEncoding.DecodeString(inps[2].String())
	if err != nil {
		return nil
	}

	res, err := _river.GenInputPassword(pass, accountPass)
	if err != nil {
		return nil
	}

	js.Global().Call("jsGenInputPassword", id, base64.StdEncoding.EncodeToString(res))
	//}(args)
	return nil
}

func dispatchProgress(progress int64) {
	js.Global().Call("jsAuthProgress", progress)
}

func parseEnvelope(m *msg.MessageEnvelope) {
	switch m.Constructor {
	case msg.C_MessageContainer:
		x := new(msg.MessageContainer)
		err := x.Unmarshal(m.Message)
		if err != nil {
			//fmt.Println("Error", err.Error())
			return
		}

		for _, envelope := range x.Envelopes {
			parseEnvelope(envelope)
		}
	case msg.C_UpdateContainer:
		x := new(msg.UpdateContainer)
		err := x.Unmarshal(m.Message)
		if err != nil {
			//fmt.Println("Error", err.Error())
			return
		}

		js.Global().Call("jsUpdate", base64.StdEncoding.EncodeToString(m.Message))
	default:
		js.Global().Call("jsDecode", true, m.RequestID, m.Constructor, base64.StdEncoding.EncodeToString(m.Message))
	}
}
