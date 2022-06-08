//
// Created by kmahyyg on 5/29/22.
// Filename: tracksock.ebpf.c

#include "headers/trackconn.ebpf.h"

// use libbpf instead of bcc, kernel force you to have license field
char LICENSE[] SEC("license") = "GPL";

// trace socket() enter
SEC("tracepoint/syscalls/sys_enter_socket")
int tracepoint__syscalls__sys_enter_socket(struct trace_event_raw_sys_enter *ctx) {
    int err = 0 ;
    // tracepoint by bpftrace
    // bpftrace -lv tracepoint:syscalls:sys_enter_socket
    if (ctx->id != __NR_socket) return 0;

    // get task struct
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // pid check
    pid_t task_pid;
    task_pid = bpf_get_current_pid_tgid();

    // new event
    struct socket_evnt valEvnt = {0};
    struct socket_evnt *evnt;

    // create evnt
    err = bpf_map_update_elem(&socket_maps, &task_pid, &valEvnt, BPF_ANY);
    if (err) {
        bpf_printk("create socket_evnt failed: %d\n", err);
        return 0;
    }

    // check existing evnt
    evnt = bpf_map_lookup_elem(&socket_maps, &task_pid);
    if (!evnt) {
        bpf_printk("no socket_evnt found for pid %d\n", task_pid);
        return 0;
    }

    // get ppid and uid and uts namespace nodename

    // https://nakryiko.com/posts/bpf-core-reference-guide/#bpf-core-read-str
    evnt->pid = task_pid;
    evnt->ppid = BPF_CORE_READ(task, real_parent, pid);
    evnt->uid = BPF_CORE_READ(task, real_cred, uid.val);

    // get uts_name from nsproxy and uts namespace name
    char *uts_name = BPF_CORE_READ(task, nsproxy, uts_ns, name.nodename);
    if (uts_name) {
        bpf_probe_read_str(evnt->uts_name, sizeof(evnt->uts_name), uts_name);
    }


    // get comm
    err = bpf_get_current_comm(evnt->comm, sizeof(evnt->comm));
    if (err) {
        bpf_printk("read task comm failed.\n");
        return 0;
    }

    // retrieve calling params, family, type, protocol
    int family = ctx->args[0];
    int type = ctx->args[1];
    int protocol = ctx->args[2];
    // set to evnt
    evnt->family = (u16)family;
    evnt->type = (u32)type;
    evnt->protocol = (u32)protocol;

    // deprecate timestamp due to ktime


    return 0;
}

// trace socket() exit
SEC("tracepoint/syscalls/sys_exit_socket")
int tracepoint__syscalls_sys_exit_socket(struct trace_event_raw_sys_exit *ctx) {
    // tracepoint by bpftrace
    // bpftrace -lv tracepoint:syscalls:sys_exit_socket
    if (ctx->id != __NR_socket) return 0;

    // init
    struct socket_evnt *evnt;

    // get pid
    u64 id = bpf_get_current_pid_tgid();
    pid_t task_pid = (pid_t)id;


    // lookup evnt from socket_maps
    int err = 0;
    evnt = bpf_map_lookup_elem(&socket_maps, &task_pid);
    if (!evnt) {
        bpf_printk("no socket_evnt found for pid %d\n", task_pid);
        return 0;
    }

    evnt->retval = ctx->ret;

    // submit to perf event
    err = bpf_perf_event_output(ctx, &s_s_events, BPF_F_CURRENT_CPU, evnt, sizeof(*evnt));
    if (err) {
        bpf_printk("perf_event_output failed: %d\n", err);
        return 0;
    }

    // cleanup, delete event
    err = bpf_map_delete_elem(&socket_maps, &task_pid);
    if (err) {
        // check /sys/kernel/debug/tracing/trace_pipe
        bpf_printk("delete socket_evnt failed: %d\n", err);
        return 0;
    }

    return 0;
}