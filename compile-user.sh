#!/bin/bash
cd ./src-go
go mod download
./scripts/build.sh
mv ./bin/ebpf_trackconn ../ebpf_trackconn