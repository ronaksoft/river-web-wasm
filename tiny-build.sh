#!/usr/bin/env bash

GOOS=js GOARCH=wasm tinygo build -o tiny.wasm -target wasm .