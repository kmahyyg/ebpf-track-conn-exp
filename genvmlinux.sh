#!/bin/bash

# Use bpftool to generate btf vmlinux header
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
