//
// Created by kmahyyg on 5/29/22.
//


#include "headers/trackconn.ebpf.h"


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

    // create empty event to map, then lookup
    // it will never be updated by another process since exit trace will be triggered and send out
    //
    // get task struct
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();

    pid_t task_pid;

    err = bpf_probe_read(&task_pid, sizeof(task->pid), &task->pid);
    if (err) {
        return 0;
    }

    // BUG HERE: do not directly access to struct scalar, copy it to some where.
    // https://stackoverflow.com/questions/69413427/bpf-verifier-rejetcs-the-use-of-an-inode-ptr-as-a-key
    err = bpf_map_update_elem(&connect_maps, &task_pid, &nEvnt, BPF_ANY);
    if (err) {
        return 0;
    }

    // get sockaddr

    valEvnt = bpf_map_lookup_elem(&connect_maps, &task_pid);
    if (!valEvnt) {
        // create failed, error
        return 0;
    }

    // fill connect_evnt , key as pid , put to hashmap
    // parse task_struct and fill the event data
    valEvnt->pid = task_pid;

    // safely attempt to get the comm
    err = bpf_get_current_comm(valEvnt->comm, sizeof(valEvnt->comm));   // in task struct, always 16
    if (err) {
        bpf_printk("read executable name from task struct comm field failed\n");
        return 0; // always return 0 to prevent from hanging around.
    }

    // get ppid and uid and uts namespace nodename

    // https://nakryiko.com/posts/bpf-core-reference-guide/#bpf-core-read-str
    valEvnt->ppid = BPF_CORE_READ(task, real_parent, pid);

    valEvnt->uid = BPF_CORE_READ(task, real_cred, uid.val);

    // get uts_name from nsproxy and uts namespace name
    BPF_CORE_READ_STR_INTO(valEvnt->uts_name, task, nsproxy, uts_ns, name.nodename);

    // sockaddr
    struct sockaddr *sockparm = (struct sockaddr *) (ctx->args[1]);
    valEvnt->socketfd = ctx->args[0];

    // chekc ipv4
    sa_family_t fam;
    err = bpf_probe_read(&fam, sizeof(sockparm->sa_family), &sockparm->sa_family);
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
    err = bpf_probe_read(&valEvnt->raddr, sizeof(sin->sin_addr.s_addr), &sin->sin_addr.s_addr);
    if (err) {
        bpf_printk("read sockaddr_in failed.\n");
        return 0;
    }

    // record rport
    u32 rport  = 0;
    err = bpf_probe_read(&rport, sizeof(sin->sin_port), &sin->sin_port);
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

    int err = 0;
    struct connect_evnt *evnt;

    // get pid
    pid_t task_pid = (pid_t) bpf_get_current_pid_tgid();

    // check if enter event has been recorded
    evnt = bpf_map_lookup_elem(&connect_maps, &task_pid);
    if (!evnt) {
        bpf_printk("no conn-event found for pid %d\n", task_pid);
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
    err = bpf_map_delete_elem(&connect_maps, &task_pid);
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
    int err = 0 ;
    // tracepoint by bpftrace
    // bpftrace -lv tracepoint:syscalls:sys_enter_socket
    if (ctx->id != __NR_socket) return 0;

    // get task struct
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // pid check
    pid_t task_pid;

    err = bpf_probe_read(&task_pid, sizeof(task->pid), &task->pid);
    if (err) {
        return 0;
    }

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
    evnt->ppid = BPF_CORE_READ(task, real_parent, pid);

    evnt->uid = BPF_CORE_READ(task, real_cred, uid.val);

    // get uts_name from nsproxy and uts namespace name
    BPF_CORE_READ_STR_INTO(evnt->uts_name, task, nsproxy, uts_ns, name.nodename);

    // get comm
    err = bpf_probe_read(&evnt->comm, sizeof(task->comm), task->comm);
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
    err = bpf_perf_event_output(ctx, &s_p_events, BPF_F_CURRENT_CPU, evnt, sizeof(*evnt));
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