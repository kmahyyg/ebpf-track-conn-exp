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

#include <asm/unistd.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#define AF_INET 2

#include "common.h"

// SEC(.maps) is a new mode for struct map definition
// perf event map in ring buffer, comm with userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u32));  // must be u32, perf event fd in perf ring buffer
    __uint(max_entries, 0);  // useless, set to 0 if you do not pass anything from usersapce to kernel
} c_t_events  SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u32));  // must be u32, perf event fd in perf ring buffer
    __uint(max_entries, 0);  // useless, set to 0 if you do not pass anything from usersapce to kernel
} s_s_events  SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u32));  // must be u32, perf event fd in perf ring buffer
    __uint(max_entries, 0);  // useless, set to 0 if you do not pass anything from usersapce to kernel
} sto_u_events  SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u32));  // must be u32, perf event fd in perf ring buffer
    __uint(max_entries, 0);  // useless, set to 0 if you do not pass anything from usersapce to kernel
} rfrom_u_events  SEC(".maps");

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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, pid_t);
    __type(value, struct sendto_evnt);
} sendto_maps SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, pid_t);
    __type(value, struct recvfrom_evnt);
} recvfrom_maps SEC(".maps");




#endif //EBPF_SNACK_TRACKDNS_TRACKCONN_EBPF_H
