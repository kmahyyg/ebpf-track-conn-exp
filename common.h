//
// Created by user on 6/7/22.
//

#ifndef EBPF_SNACK_TRACKDNS_COMMON_H
#define EBPF_SNACK_TRACKDNS_COMMON_H

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


#endif //EBPF_SNACK_TRACKDNS_COMMON_H
