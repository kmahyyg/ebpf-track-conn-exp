.PHONY: clean kernonly useronly

all: clean kernonly useronly

clean:
	rm -rf *.o
	rm -rf *.skel.h
	rm -rf ./headers/vmlinux.h
	rm -rf ./src-go/cmd/bpf_bpf*.go
	rm -rf ./src-go/cmd/bpf_bpf*.o

kernonly:
	bash ./compile-kern.sh

useronly:
	bash ./compile-user.sh

