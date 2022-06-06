//
// Created by kmahyyg on 5/29/22.
//

#include "trackconn.ebpf.h"

// use libbpf instead of bcc, kernel force you to have license field
char LICENSE[] SEC("license") = "GPL";

// trace connect() enter
SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    // tracepoint by bpftrace
    // bpftrace -lv tracepoint:syscalls:sys_enter_connect
    if (ctx->id != __NR_connect) return 0;

    int err = 0 ;
    // must init to prevent security issue
    struct connect_evnt nEvnt = { 0 };
    struct connect_evnt *valEvnt = { 0 };

    // get task struct
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();

    // create empty event to map, then lookup
    // it will never be updated by another process since exit trace will be triggered and send out
    err = bpf_map_update_elem(&connect_maps, &task->pid, &nEvnt, BPF_ANY);
    if (err) {
        return 0;
    }

    // get sockaddr
    valEvnt = bpf_map_lookup_elem(&connect_maps, &task->pid);
    if (!valEvnt) {
        // create failed, error
        return 0;
    }

    // fill connect_evnt , key as pid , put to hashmap
    // parse task_struct and fill the event data
    valEvnt->pid = task->pid;

    // safely attempt to get the comm
    err = bpf_get_current_comm(&valEvnt->comm, sizeof(valEvnt->comm));   // in task struct, always 16
    if (err) {
        bpf_printk("read executable name from task struct comm field failed\n");
        return 0; // always return 0 to prevent from hanging around.
    }

    // get ppid and uid
    valEvnt->ppid = task->real_parent->pid;
    valEvnt->uid = task->real_cred->uid.val;

    // get uts_name from nsproxy and uts namespace name
    struct uts_namespace *ns = task->nsproxy->uts_ns;
    err = bpf_probe_read(&valEvnt->uts_name, sizeof(ns->name.nodename), ns->name.nodename);
    if (err) {
        bpf_printk("read utsname nodename from task struct failed.\n");
        return 0;
    }

    // sockaddr
    struct sockaddr *sockparm = (struct sockaddr *) (ctx->args[1]);
    valEvnt->socketfd = ctx->args[0];

    // chekc ipv4
    sa_family_t fam;
    err = bpf_probe_read(&fam, sizeof(fam), &sockparm->sa_family);
    if (err) {
        bpf_printk("read sockaddr family failed.\n");
        return 0;
    }
    if (fam != AF_INET) {
        // only support IPv4 currently
        return 0;
    }

    // record raddr
    struct sockaddr_in *sin = (struct sockaddr_in *) (sockparm);
    err = bpf_probe_read(&valEvnt->raddr, sizeof(valEvnt->raddr), &sin->sin_addr.s_addr);
    if (err) {
        bpf_printk("read sockaddr_in failed.\n");
        return 0;
    }

    // record rport
    u32 rport  = 0;
    err = bpf_probe_read(&rport, sizeof(sin->sin_port),&sin->sin_port);
    if (err) {
        bpf_printk("read sockaddr_in port failed.\n");
        return 0;
    }
    valEvnt->rport = bpf_ntohs(rport);

    // set timestamp
    valEvnt->ts_us = bpf_ktime_get_ns() / 1000;
    return 0;
}

// trace connect() exit
SEC("tracepoint/syscalls/sys_exit_connect")
int tracepoint__syscalls__sys_exit_connect(struct trace_event_raw_sys_exit *ctx) {
    if (ctx->id != __NR_connect) return 0;
    pid_t pid;

    int err = 0;
    struct connect_evnt *evnt;

    // get pid
    pid = (pid_t) bpf_get_current_pid_tgid();

    // check if enter event has been recorded
    evnt = bpf_map_lookup_elem(&connect_maps, &pid);
    if (!evnt) {
        bpf_printk("no conn-event found for pid %d\n", pid);
        return 0;
    }

    // update retval
    evnt->retval = ctx->ret;

    // submit to perf event
    err = bpf_perf_event_output(ctx, &c_p_events, BPF_F_CURRENT_CPU, evnt, sizeof(*evnt));
    if (err) {
        bpf_printk("perf_event_output failed: %d\n", err);
        return 0;
    }

    // cleanup, delete event
    err = bpf_map_delete_elem(&connect_maps, &pid);
    if (err) {
        // check /sys/kernel/debug/tracing/trace_pipe
        bpf_printk("delete connect_evnt failed: %d\n", err);
        return 0;
    }
     return 0;
}


// trace socket() enter
SEC("tracepoint/syscalls/sys_enter_socket")
int tracepoint__syscalls__sys_enter_socket(struct trace_event_raw_sys_enter *ctx) {
    // tracepoint by bpftrace
    // bpftrace -lv tracepoint:syscalls:sys_enter_socket
    if (ctx->id != __NR_socket) return 0;

    // get task struct
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // pid check
    pid_t pid = task->pid;

    // new event
    struct socket_evnt *valEvnt = {0};
    struct socket_evnt *evnt;

    // create evnt
    int err = 0 ;
    err = bpf_map_update_elem(&socket_maps, &pid, &valEvnt, BPF_ANY);
    if (err) {
        bpf_printk("create socket_evnt failed: %d\n", err);
        return 0;
    }

    // check existing evnt
    evnt = bpf_map_lookup_elem(&socket_maps, &pid);
    if (!evnt) {
        bpf_printk("no socket_evnt found for pid %d\n", pid);
        return 0;
    }

    // get ppid from task struct and store
    evnt->ppid = task->real_parent->pid;
    // get uid from task struct and store
    evnt->uid = task->real_cred->uid.val;

    // get comm
    err = bpf_probe_read(&evnt->comm, sizeof(evnt->comm), task->comm);
    if (err) {
        bpf_printk("read task comm failed.\n");
        return 0;
    }

    // get uts hostname from nsproxy
    struct uts_namespace *ns = task->nsproxy->uts_ns;
    err = bpf_probe_read(&evnt->uts_name, sizeof(evnt->uts_name), ns->name.nodename);
    if (err) {
        bpf_printk("read utsname failed.\n");
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

    // set timestamp
    evnt->ts_us = bpf_ktime_get_ns() / 1000;


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
    pid_t pid = (pid_t)id;


    // lookup evnt from socket_maps
    int err = 0;
    evnt = bpf_map_lookup_elem(&socket_maps, &pid);
    if (!evnt) {
        bpf_printk("no socket_evnt found for pid %d\n", pid);
        return 0;
    }

    evnt->retval = ctx->ret;

    // submit to perf event
    err = bpf_perf_event_output(ctx, &s_p_events, BPF_F_CURRENT_CPU, evnt, sizeof(*evnt));
    if (err) {
        bpf_printk("perf_event_output failed: %d\n", err);
        return 0;
    }

    // cleanup, delete event
    err = bpf_map_delete_elem(&socket_maps, &pid);
    if (err) {
        // check /sys/kernel/debug/tracing/trace_pipe
        bpf_printk("delete socket_evnt failed: %d\n", err);
        return 0;
    }

    return 0;
}