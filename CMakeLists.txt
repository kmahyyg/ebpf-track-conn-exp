cmake_minimum_required(VERSION 3.22)
project(ebpf_snack_trackdns C)

set(CMAKE_C_STANDARD 11)

add_executable(ebpf_snack_trackdns trackconn.ebpf.c)
