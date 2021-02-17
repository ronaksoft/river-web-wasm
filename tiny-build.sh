#!/usr/bin/env bash

GOOS=js GOARCH=wasm /Users/hamidrezakk/go/bin/tinygo build -o tiny.wasm -target wasm .