//
// Created by user on 5/29/22.
//

#ifndef EBPF_SNACK_TRACKDNS_TRACKCONN_EBPF_H
#define EBPF_SNACK_TRACKDNS_TRACKCONN_EBPF_H



#define CORE_BPF
#ifdef CORE_BPF
    #include "vmlinux.h"
#else
    #include <linux/types.h>
#endif

#include <bpf/bpf_helpers.h>
#include <asm/unistd.h>
#include <bpf/bpf_endian.h>

#define AF_INET 2

// internal context

struct socket_evnt {
    // evnt type for parse
    // --------------------------- PUBLIC PART
    __u64 ts_us;
    // 32 bit
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    // cmdline for process
    char comm[16];
    // hostname in uts namespace to distinguish between different containers
    char uts_name[65];
    // --------------------------- PRIVATE PART
    // socket() return socket fd number
    __s64 retval;
    // socket info
    __u16 family;
    __u32 type;
    __u32 protocol;
    // static padding for 64 bit alignment

};

// internal context

struct connect_evnt {
    // --------------------------- PUBLIC PART
    // evnt type for parse
    __u64 ts_us;
    // 32 bit
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    // executable name for process
    char comm[16];
    // hostname in uts namespace to distinguish between different containers
    char uts_name[65];
    // --------------------------- PRIVATE PART
    __u16 family;
    __u32 raddr;
    __u16 rport;
    // connect with socket call
    __u32 socketfd;
    // response info
    __s64 retval;
};

// SEC(.maps) is a new mode for struct map definition
// perf event map in ring buffer, comm with userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u32));  // must be u32, perf event fd in perf ring buffer
    __uint(max_entries, 0);  // useless, set to 0 if you do not pass anything from usersapce to kernel
} c_p_events  SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u32));  // must be u32, perf event fd in perf ring buffer
    __uint(max_entries, 0);  // useless, set to 0 if you do not pass anything from usersapce to kernel
} s_p_events  SEC(".maps");

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
