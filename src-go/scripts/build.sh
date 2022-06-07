#!/bin/bash

export BPF_CLANG=clang
export BPF_CFLAGS="-O2 -g -Wall -Werror"
cd ./cmd
rm -rf ./bpf_bpf*
go generate ./main.go