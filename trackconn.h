//
// Created by user on 5/29/22.
//

#ifndef EBPF_SNACK_TRACKDNS_TRACKCONN_H
#define EBPF_SNACK_TRACKDNS_TRACKCONN_H


#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
int FLAG_BPF_LIBBPF_DEBUG = 0;
int print_libbpf_log(enum libbpf_print_level level, const char *format, va_list args);



#endif //EBPF_SNACK_TRACKDNS_TRACKCONN_H
