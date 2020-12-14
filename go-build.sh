#!/usr/bin/env bash

GOOS=js GOARCH=wasm go build -ldflags="-s -w" -o river.wasm .