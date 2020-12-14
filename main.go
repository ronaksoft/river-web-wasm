package main

import (
	"encoding/base64"
	"fmt"
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
	global.Set("wasmInit", js.FuncOf(authStep1))
	global.Set("wasmAuthStep1", js.FuncOf(authStep1))
	global.Set("wasmAuthStep2", js.FuncOf(authStep2))
	global.Set("wasmAuthStep3", js.FuncOf(authStep3))
	global.Set("wasmDecode", js.FuncOf(decode))
	global.Set("wasmEncode", js.FuncOf(encode))
	global.Set("wasmGenSrpHash", js.FuncOf(generateSrpHash))
	global.Set("wasmGenInputPassword", js.FuncOf(generateInputPassword))
	<-done

	fmt.Println("Bye Wasm !")
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

func authStep1(this js.Value, args []js.Value) interface{} {
	go func() {
		bytes := _river.AuthStep1(dispatchProgress)
		js.Global().Call("jsAuthStep1", base64.StdEncoding.EncodeToString(bytes))
	}()
	return nil
}

func authStep2(this js.Value, args []js.Value) interface{} {
	go func(inps []js.Value) {
		enc, err := base64.StdEncoding.DecodeString(args[0].String())
		if err != nil {
			return
		}

		bytes, err := _river.AuthStep2(enc, dispatchProgress)
		if err != nil {
			return
		}

		js.Global().Call("jsAuthStep2", base64.StdEncoding.EncodeToString(bytes))
	}(args)

	return nil
}

func authStep3(this js.Value, args []js.Value) interface{} {
	go func(inps []js.Value) {
		enc, err := base64.StdEncoding.DecodeString(inps[0].String())
		if err != nil {
			return
		}

		bytes, err := _river.AuthStep3(enc, dispatchProgress)
		if err != nil {
			return
		}

		js.Global().Call("jsAuthStep3", base64.StdEncoding.EncodeToString(bytes))
	}(args)

	return nil
}

func decode(this js.Value, args []js.Value) interface{} {
	go func(inps []js.Value) {
		enc, err := base64.StdEncoding.DecodeString(inps[0].String())
		if err == nil {
			return
		}

		env, err := _river.Decode(enc)
		if err == nil || env == nil {
			return
		}

		js.Global().Call("jsDecode", env.RequestID, env.Constructor, base64.StdEncoding.EncodeToString(env.Message))
	}(args)

	return nil
}

func encode(this js.Value, args []js.Value) interface{} {
	go func(inps []js.Value) {
		env := new(msg.MessageEnvelope)

		env.RequestID = uint64(args[0].Int())
		env.Constructor = int64(args[1].Int())
		enc, err := base64.StdEncoding.DecodeString(args[2].String())
		if err != nil {
			return
		}
		env.Message = enc

		if len(args) > 4 {
			teamId := args[3].String()
			teamAccessHash := args[4].String()
			if teamId != "0" && teamAccessHash != "0" {
				env.Header = river.TeamHeader(teamId, teamAccessHash)
			}
		}

		bytes, err := _river.Encode(env)
		if err == nil {
			return
		}

		js.Global().Call("jsEncode", env.RequestID, base64.StdEncoding.EncodeToString(bytes))
	}(args)

	return nil
}

func generateSrpHash(this js.Value, inps []js.Value) interface{} {
	go func(args []js.Value) {
		id := args[0].Int()
		pass, err := base64.StdEncoding.DecodeString(args[1].String())
		if err != nil {
			return
		}

		algorithm := args[2].Int()
		algorithmData, err := base64.StdEncoding.DecodeString(args[3].String())
		if err != nil {
			return
		}

		res, err := _river.GenSrpHash(pass, int64(algorithm), algorithmData)
		if err != nil {
			return
		}

		js.Global().Call("jsGenSrpHash", id, base64.StdEncoding.EncodeToString(res))
	}(inps)
	return nil
}

func generateInputPassword(this js.Value, inps []js.Value) interface{} {
	go func(args []js.Value) {
		id := args[0].Int()
		pass, err := base64.StdEncoding.DecodeString(args[1].String())
		if err != nil {
			return
		}

		accountPass, err := base64.StdEncoding.DecodeString(args[2].String())
		if err != nil {
			return
		}

		res, err := _river.GenInputPassword(pass, accountPass)
		if err != nil {
			return
		}

		js.Global().Call("jsGenInputPassword", id, base64.StdEncoding.EncodeToString(res))
	}(inps)
	return nil
}

func dispatchProgress(progress int64) {
	js.Global().Call("jsAuthProgress", progress)
}
