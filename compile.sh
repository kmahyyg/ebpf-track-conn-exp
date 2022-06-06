#!/bin/bash

# Use -Werror if treat warning as error
clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -D__TARGER_ARCH_x86 -c trackconn.ebpf.c -o trackconn.ebpf.o
clang -g -O2 -lpthread -c trackconn.c -o trackconn.o

