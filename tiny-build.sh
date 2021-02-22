#!/usr/bin/env bash

GOOS=js GOARCH=wasm /Users/hamidrezakk/go/bin/tinygo build -no-debug -o /Users/hamidrezakk/ronak/river/web-app/public/bin/river-tiny.wasm -target wasm .