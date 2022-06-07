#!/bin/bash

rm *.o
rm *.skel.h
rm ./headers/vmlinux.h

./mod-environment.sh
./genvmlinux.sh


# Use -Werror if treat warning as error
clang -O2 -g -Wall -target bpf -I/usr/include/x86_64-linux-gnu -D__TARGER_ARCH_x86 -c trackconn.ebpf.c -o trackconn.ebpf.o
./genskel.sh
clang -g -O2 -Wall -c trackconn.c -o trackconn.o


