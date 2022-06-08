#!/bin/bash

./mod-environment.sh
./genvmlinux-kern.sh

# Use -Werror if treat warning as error
clang -O2 -g -Wall -target bpf -I/usr/include/x86_64-linux-gnu -D__TARGER_ARCH_x86 -c trackconn.ebpf.c -o trackconn.ebpf.o
./genskel-kern.sh
#clang -g -O2 -Wall -c trackconn.c -o trackconn.o

