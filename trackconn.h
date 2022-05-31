//
// Created by user on 5/29/22.
//

#ifndef EBPF_SNACK_TRACKDNS_TRACKCONN_H
#define EBPF_SNACK_TRACKDNS_TRACKCONN_H


#include <bpf/libbpf.h>
#include <bpf/bpf.h>

// use for bump rlimit
#include <sys/resource.h>

// use for linux types
#include "trackconn.ebpf.h"
#include "trackconn.ebpf.skel.h"


int FLAG_BPF_LIBBPF_DEBUG = 0;
int print_libbpf_log(enum libbpf_print_level level, const char *format, va_list args);
void handle_lost_events(void *ctz, int cpu, __u64 lost_cnt);
void handle_event(void *ctx, int cpu, void *data, __u32 data_sz);

#endif //EBPF_SNACK_TRACKDNS_TRACKCONN_H
