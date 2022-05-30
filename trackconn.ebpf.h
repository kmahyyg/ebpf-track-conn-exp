//
// Created by user on 5/29/22.
//

#ifndef EBPF_SNACK_TRACKDNS_TRACKCONN_EBPF_H
#define EBPF_SNACK_TRACKDNS_TRACKCONN_EBPF_H


#include <bpf/libbpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bits/socket.h>
#include <bpf/bpf_core_read.h>
#include <asm/unistd.h>
#include "vmlinux.h"
#include <bpf/bpf_endian.h>

static const u16 YCUSTOM_EVNT_TYPE_SOCKET = 1;
static const u16 YCUSTOM_EVNT_TYPE_CONNECT = 2;

// internal context
#pragma pack(8)
struct socket_evnt {
    // evnt type for parse
    u16 evnt_type;  // 1 - socket_ENTER, 2 - connect_ENTER
    // --------------------------- PUBLIC PART
    u64 ts_us;
    // 32 bit
    u32 pid;
    u32 ppid;
    u32 uid;
    // cmdline for process
    char comm[16];
    // hostname in uts namespace to distinguish between different containers
    char uts_name[65];
    // --------------------------- PRIVATE PART
    // socket() return socket fd number
    s64 retval;
    // socket info
    u16 family;
    u32 type;
    u32 protocol;
    // static padding for 64 bit alignment

};

// internal context
#pragma pack(8)
struct connect_evnt {
    // --------------------------- PUBLIC PART
    u64 ts_us;
    // evnt type for parse
    u16 evnt_type;  // 1 - socket, 2 - connect
    // 32 bit
    u32 pid;
    u32 ppid;
    u32 uid;
    // executable name for process
    char comm[16];
    // hostname in uts namespace to distinguish between different containers
    char uts_name[65];
    // --------------------------- PRIVATE PART
    u16 family;
    u32 raddr;
    u16 rport;
    // connect with socket call
    u32 socketfd;
    // response info
    s64 retval;
};

// SEC(.maps) is a new mode for struct map definition
// perf event map in ring buffer, comm with userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(u32));  // must be u32, perf event fd in perf ring buffer
    __uint(max_entries, 0);  // useless, set to 0 if you do not pass anything from usersapce to kernel
} events  SEC(".maps");

// define hash-map with event connect and socket
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, pid_t);
    __type(value, struct connect_evnt);
} connect_maps  SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, pid_t);
    __type(value, struct socket_evnt);
} socket_maps  SEC(".maps");


#endif //EBPF_SNACK_TRACKDNS_TRACKCONN_EBPF_H
