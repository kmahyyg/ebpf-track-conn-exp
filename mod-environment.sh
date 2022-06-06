#!/bin/bash

# increase memlock limit
sudo ulimit -l unlimited

# increase max file descriptors if possible
sudo ulimit -n unlimited

# mount debugfs to /sys/kernel/debug
sudo mount -t debugfs debugfs /sys/kernel/debug

# check if /proc/kallsyms exists, then echo result
if [ -f /proc/kallsyms ]; then
  echo "kallsyms exists"
else
  echo "kallsyms does not exist"
fi

# check if kernel support for BTF
if [ -f /sys/kernel/btf/vmlinux ]; then
  echo "BTF is supported"
else
  echo "BTF is not supported"
fi

# check BTF and BPF related information in /proc/config.gz or /proc/config
if [ -f /proc/config.gz ]; then
  echo "BTF and BPF related information in /proc/config.gz"
  zcat /proc/config.gz | grep -i bpf
  zcat /proc/config.gz | grep -i btf
elif [ -f /proc/config ]; then
  echo "BTF and BPF related information in /proc/config"
  cat /proc/config | grep -i bpf
  cat /proc/config | grep -i btf
else
  echo "BTF and BPF related information is not available"
fi


exit 0
