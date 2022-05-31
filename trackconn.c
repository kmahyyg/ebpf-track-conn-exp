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

    // set error and debug info callback
    libbpf_set_print(print_libbpf_log);

    //  open bpf appli
    struct trackconn_ebpf *skel;
    struct perf_buffer_opts pb_opts;
    struct perf_buffer *pb;

    skel = trackconn_ebpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open eBPF program\n");
        return 1;
    }

    // load and verify
    err = trackconn_ebpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load and verify eBPF program\n");
        goto cleanup;
    }

    // attach to tp handler
    err = trackconn_ebpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach to tp handler\n");
        goto cleanup;
    }

    // setup evnt callbacks
    pb_opts.sample_cb = handle_events;

cleanup:
    perf_buffer__free(pb);
    trackconn_ebpf__destroy(skel);
    return err;



}

// set custom log handler for libbpf
int print_libbpf_log(enum libbpf_print_level level, const char *format, va_list args) {
    if (FLAG_BPF_LIBBPF_DEBUG || level != LIBBPF_DEBUG){
        vfprintf(stderr, format, args);
        return 0;
    }
    return 1;
}

void handle_lost_events(void *ctz, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "lost %llu events on CPU %d\n", lost_cnt, cpu);
}


void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    // https://elixir.bootlin.com/linux/latest/source/tools/bpf/bpftool/map_perf_ring.c#L39


}
