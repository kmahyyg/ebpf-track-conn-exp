#!/bin/bash

export BPF_CLANG=clang
export BPF_CFLAGS="-O2 -g -Wall -Werror"
cd ../cmd
go generate ./main.go