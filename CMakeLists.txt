cmake_minimum_required(VERSION 3.22)
project(ebpf_snack_trackdns C)

set(CMAKE_C_STANDARD 99)

add_executable(ebpf_snack_tracksock tracksock.ebpf.c headers/common.h headers/trackconn.ebpf.h)
add_executable(ebpf_snack_userland archived/trackconn.c archived/trackconn.h headers/common.h headers/trackconn.ebpf.h)
add_executable(ebpf_snack_tracktcp tracktcp.ebpf.c headers/common.h headers/trackconn.ebpf.h)
add_executable(ebpf_snack_trackudp trackudp.ebpf.c headers/common.h headers/trackconn.ebpf.h)
