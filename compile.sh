#!/bin/bash
clang -O2 -g -Wall -Werror -target bpf -I/usr/include/x86_64-linux-gnu -D__TARGER_ARCH_x86 -c trackconn.ebpf.c -o trackconn.ebpf.o

