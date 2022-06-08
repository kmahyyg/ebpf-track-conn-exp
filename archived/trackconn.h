//
// Created by user on 5/29/22.
//

#ifndef EBPF_SNACK_TRACKDNS_TRACKCONN_H
#define EBPF_SNACK_TRACKDNS_TRACKCONN_H

// use for bump rlimit
#include <sys/resource.h>

// use for linux types
#include "../headers/common.h"
#include <bpf/bpf_endian.h>
#include "../tracksock.ebpf.skel.h"


struct poll_pbuf_event_data {
    struct perf_buffer *pb_data;
    int pb_type;
} poll_pbuf_event_data_ptype;

int FLAG_BPF_LIBBPF_DEBUG = 0;

int print_libbpf_log(enum libbpf_print_level level, const char *format, va_list args);
void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt);
void handle_event_c(void *ctx, int cpu, void *data, __u32 data_sz);
void handle_event_s(void *ctx, int cpu, void *data, __u32 data_sz);
void *poll_event_from_perf_buf(struct poll_pbuf_event_data *pbEvntData);


#endif //EBPF_SNACK_TRACKDNS_TRACKCONN_H
