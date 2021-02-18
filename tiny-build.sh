#!/usr/bin/env bash

GOOS=js GOARCH=wasm /Users/hamidrezakk/go/bin/tinygo build -o /Users/hamidrezakk/ronak/river/web-app/public/bin/river-tiny.wasm -target wasm .