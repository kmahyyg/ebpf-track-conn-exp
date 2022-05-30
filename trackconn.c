//
// Created by user on 5/29/22.
//

#include "trackconn.h"

int main(int argc, char **argv) {
    int err = 0;

    // first bump rlimit for MEMLOCK
    struct rlimit r_lim_new = {
            .rlim_cur = RLIM_INFINITY,
            .rlim_max = RLIM_INFINITY
    };

    err = setrlimit(RLIMIT_MEMLOCK, &r_lim_new);
    if (err) {
        fprintf(stderr, "failed to set rlimit");
        return 1;
    }

    libbpf_set_print(print_libbpf_log);

    // load BPF program in userspace

}

// set custom log handler for libbpf
int print_libbpf_log(enum libbpf_print_level level, const char *format, va_list args) {
    if (FLAG_BPF_LIBBPF_DEBUG || level != LIBBPF_DEBUG){
        vfprintf(stderr, format, args);
        return 0;
    }
    return 1;
}