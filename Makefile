.PHONY: clean kernonly useronly

all: clean kernonly useronly

clean:
	rm -rf *.o
	rm -rf *.skel.h
	rm -rf *.gen.c
	rm -rf ./headers/vmlinux.h
	rm -rf ./src-go/cmd/bpf_bpf*.go
	rm -rf ./src-go/cmd/bpf_bpf*.o
	rm -rf ebpf_trackconn

kernonly:
	bash ./compile-kern.sh

useronly:
	bash ./compile-user.sh

