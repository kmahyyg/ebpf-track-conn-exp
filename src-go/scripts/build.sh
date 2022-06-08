#!/bin/bash

export BPF_CLANG=clang
export BPF_CFLAGS="-O2 -g -Wall -Werror"
export CGO_ENABLED=0
cd ./cmd
rm -rf ./bpf_bpf*
go generate ./main.go
cd ..
go build -o ./bin/ebpf_trackconn -ldflags='-s -w' -trimpath ./cmd