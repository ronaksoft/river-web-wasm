#!/usr/bin/env bash

GOOS=js GOARCH=wasm go build -ldflags="-s -w" -o /Users/hamidrezakk/ronak/river/web-app/public/bin/river.wasm .