#!/usr/bin/env bash

GOOS=js GOARCH=wasm /Users/hamidrezakk/go/bin/tinygo build -no-debug -tags=math_big_pure_go -o /Users/hamidrezakk/ronak/river/web-app/public/bin/river-tiny.wasm -target wasm .