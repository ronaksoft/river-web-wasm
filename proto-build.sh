#!/usr/bin/env bash

rm ./msg/*.pb.go

protoc -I=$GOPATH/src -I=./msg --gogofaster_out=./msg ./msg/*.proto

rm ./connection/river_conn_easyjson.go

easyjson ./connection/river_conn.go