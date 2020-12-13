#!/usr/bin/env bash

rm ./msg/*.pb.go

protoc -I=$GOPATH/src -I=./msg --gogofaster_out=./msg ./msg/*.proto