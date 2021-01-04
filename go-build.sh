#!/usr/bin/env bash

GOOS=js GOARCH=wasm GODEBUG=gcstoptheworld=1 GOGC=20 go build -ldflags="-s -w" -o /Users/hamidrezakk/ronak/river/web-app/public/bin/river.wasm .