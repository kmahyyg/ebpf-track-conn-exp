#!/bin/bash

./mod-environment.sh
./genvmlinux-kern.sh

echo '// DO NOT MODIFY -- AUTO GENERATED FILE' > trackall.conn.ebpf.gen.c
echo '#include "headers/trackconn.ebpf.h"' >> trackall.conn.ebpf.gen.c
printf "\n" >> trackall.conn.ebpf.gen.c
echo 'char LICENSE[] SEC("license") = "GPL";' >> trackall.conn.ebpf.gen.c
printf "\n" >> trackall.conn.ebpf.gen.c
cat ./*.ebpf.c | grep -v '#include' | grep -v 'LICENSE\[\]' >> trackall.conn.ebpf.gen.c

# Use -Werror if treat warning as error
clang -O2 -g -Wall -target bpf -I/usr/include/x86_64-linux-gnu -D__TARGER_ARCH_x86 -c trackall.conn.ebpf.gen.c -o trackall.conn.ebpf.gen.o
./genskel-kern.sh
#clang -g -O2 -Wall -c trackconn.c -o trackconn.o


