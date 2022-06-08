//
// Created by user on 6/7/22.
//

#ifndef EBPF_SNACK_TRACKDNS_COMMON_H
#define EBPF_SNACK_TRACKDNS_COMMON_H

// internal context

struct socket_evnt {
    // evnt type for parse
    // --------------------------- PUBLIC PART
    // 32 bit
    __u64 pid;
    __u64 ppid;
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
    // 32 bit
    __u64 pid;
    __u64 ppid;
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


struct sendto_evnt {
    // evnt type for parse
    // --------------------------- PUBLIC PART
    // 32 bit
    __u64 pid;
    __u64 ppid;
    __u32 uid;
    // cmdline for process
    char comm[16];
    // hostname in uts namespace to distinguish between different containers
    char uts_name[65];
    // return value
    __s64 retval;
    // --------------------------- PRIVATE PART
    __u16 family;
    __u32 raddr;
    __u16 rport;
};

struct recvfrom_evnt {
    // evnt type for parse
    // --------------------------- PUBLIC PART
    // 32 bit
    __u64 pid;
    __u64 ppid;
    __u32 uid;
    // cmdline for process
    char comm[16];
    // hostname in uts namespace to distinguish between different containers
    char uts_name[65];
    // return value
    __s64 retval;
    // --------------------------- PRIVATE PART
    __u16 family;
    __u32 saddr;
    __u16 sport;
};

#endif //EBPF_SNACK_TRACKDNS_COMMON_H
