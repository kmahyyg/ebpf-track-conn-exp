//
// Created by user on 5/29/22.
//

#include "trackconn.ebpf.skel.h"
#include <sys/resource.h>
#include <pthread.h>
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
    struct perf_buffer_opts pb_opts_s, pb_opts_c;
    struct perf_buffer *pb_s, *pb_c;

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

    // setup evnt callbacks for socket
    pb_opts_s.sample_cb = handle_event_s;
    pb_opts_s.lost_cb = handle_lost_events;
    pb_s = perf_buffer__new(bpf_map__fd(skel->maps.s_p_events), 64, &pb_opts_s);
    err = libbpf_get_error(pb_s);
    if (err) {
        pb_s = NULL;
        fprintf(stderr, "failed to open perf buf pb_s: %d\n",err);
        goto cleanup;
    }

    // setup evnt callbacks for connect
    pb_opts_c.sample_cb = handle_event_c;
    pb_opts_c.lost_cb = handle_lost_events;
    pb_c = perf_buffer__new(bpf_map__fd(skel->maps.c_p_events), 64, &pb_opts_c);
    err = libbpf_get_error(pb_c);
    if (err) {
        pb_c = NULL;
        fprintf(stderr, "failed to open perf buf pb_c: %d\n", err);
        goto cleanup;
    }

    printf("initialization done.\n");

    // poll events
    // two threads for that.
    pthread_t tid_s, tid_c;

    // thread 1 for socket
    struct poll_pbuf_event_data *pped_s = malloc(sizeof poll_pbuf_event_data_ptype);
    memset(pped_s, 0, sizeof poll_pbuf_event_data_ptype);
    pped_s->pb_type = 0;
    pped_s->pb_data = pb_s;
    pthread_create(&tid_s, NULL, poll_event_from_perf_buf, (void *)pped_s);

    // thread 2 for connect - main thread
    struct poll_pbuf_event_data *pped_c = malloc(sizeof poll_pbuf_event_data_ptype);
    memset(pped_c, 0, sizeof poll_pbuf_event_data_ptype);
    pped_c->pb_type = 1;
    pped_c->pb_data = pb_c;
    poll_event_from_perf_buf(pped_c);


cleanup:
    perf_buffer__free(pb_s);
    perf_buffer__free(pb_c);
    trackconn_ebpf__destroy(skel);
    printf("program exited, errcode: %d\n", err);
    pthread_exit(0);
}

void *poll_event_from_perf_buf(struct poll_pbuf_event_data *pbEvntData){
    // type=0, socket; type=1, connect;
    int err = 0;
    while ( (err = perf_buffer__poll(pbEvntData->pb_data, 100)) >= 0 );
    printf("err when polling from buf, type: %d , err: %d \n", pbEvntData->pb_type, err);
}

// set custom log handler for libbpf
int print_libbpf_log(enum libbpf_print_level level, const char *format, va_list args) {
    if (FLAG_BPF_LIBBPF_DEBUG || level != LIBBPF_DEBUG){
        vfprintf(stderr, format, args);
        return 0;
    }
    return 1;
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "lost %llu events on CPU %d\n", lost_cnt, cpu);
}


void handle_event_c(void *ctx, int cpu, void *data, __u32 data_sz) {
    // https://elixir.bootlin.com/linux/latest/source/tools/bpf/bpftool/map_perf_ring.c#L39
    struct connect_evnt *e ;
    time_t ts;
    struct tm *tm;
    char ts_str[64];

    e = data;
    ts = e->ts_us;
    tm = localtime(&ts);
    strftime(ts_str, sizeof ts_str, "[%Y-%m-%d %H:%M:%S]", tm);

    // force terminated string
    e->comm[15] = '\0';
    e->uts_name[64] = '\0';



    printf("[SOCK] %s , %d (Parent: %d) %s, %d @ %s, ret: %lld, F:%d , FD:%d, Rem: %u:%d \n", ts_str, e->pid, e->ppid,
           e->comm, e->uid, e->uts_name, e->retval, e->family, e->socketfd, e->raddr, bpf_ntohs(e->rport));

}

void handle_event_s(void *ctx, int cpu, void *data, __u32 data_sz) {
    // https://elixir.bootlin.com/linux/latest/source/tools/bpf/bpftool/map_perf_ring.c#L39
    struct socket_evnt *e ;
    time_t ts;
    struct tm *tm;
    char ts_str[64];

    e = data;
    ts = e->ts_us;
    tm = localtime(&ts);
    strftime(ts_str, sizeof ts_str, "[%Y-%m-%d %H:%M:%S]", tm);

    // force terminated string
    e->comm[15] = '\0';
    e->uts_name[64] = '\0';

    printf("[SOCK] %s , %d (Parent: %d) %s, %d @ %s, ret: %lld, F:%d , T:%d, P:%d \n", ts_str, e->pid, e->ppid,
           e->comm, e->uid, e->uts_name, e->retval, e->family, e->type, e->protocol);
}