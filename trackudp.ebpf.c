//
// Created by user on 6/8/22.
// Filename: trackudp.ebpf.c

#include "headers/trackconn.ebpf.h"

char LICENSE[] SEC("license") = "GPL";
// trace sendto(a,b,c,d, const struct sockaddr* dest_addr, f) enter
SEC("tracepoint/syscalls/sys_enter_sendto")
int tracepoint__syscalls__sys_enter_sendto(struct trace_event_raw_sys_enter *ctx){
    if (ctx -> id != __NR_sendto) return 0;
    int err = 0;
    struct sendto_evnt nEvnt = { 0 };
    struct sendto_evnt *valEvnt = { 0 };

    // get pid, task struct
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    pid_t task_pid;
    task_pid = bpf_get_current_pid_tgid();

    err = bpf_map_update_elem(&sendto_maps, &task_pid, &nEvnt, BPF_ANY);
    if (err) {
        return 0;
    }

    valEvnt = bpf_map_lookup_elem(&sendto_maps, &task_pid);
    if (!valEvnt) {
        // create failed, error
        return 0;
    }

    valEvnt->pid=task_pid;

    // get comm
    err = bpf_get_current_comm(valEvnt->comm, sizeof(valEvnt->comm));
    if (err) {
        bpf_printk("read executable name from task struct comm field failed\n");
        return 0; // always return 0 to prevent from hanging around.
    }

    // get ppid and uid and uts namespace nodename
    valEvnt->ppid = BPF_CORE_READ(task, real_parent, pid);
    valEvnt->uid = BPF_CORE_READ(task, real_cred, uid.val);

    char *uts_name = BPF_CORE_READ(task, nsproxy, uts_ns, name.nodename);
    if (uts_name) {
        bpf_probe_read(&valEvnt->uts_name, sizeof(valEvnt->uts_name), uts_name);
    }

    struct sockaddr *dest_addr = (struct sockaddr *) ctx->args[4];
    // check if ipv4
    sa_family_t fam;
    err = bpf_probe_read(&fam, sizeof(dest_addr->sa_family), &dest_addr->sa_family);
    if (err) {
        bpf_printk("read sockaddr family failed.\n");
        return 0;
    }
    if (fam != AF_INET) {
        // only support IPv4 currently
        return 0;
    }
    valEvnt->family=fam;

    // sin
    struct sockaddr_in *sin = (struct sockaddr_in *) (dest_addr);
    err = bpf_probe_read(&valEvnt->raddr, sizeof(sin->sin_addr.s_addr), &sin->sin_addr.s_addr);
    if (err) {
        bpf_printk("read sockaddr ipv4 address failed.\n");
        return 0;
    }
    u32 rport = 0;
    err = bpf_probe_read(&rport, sizeof(sin->sin_port), &sin->sin_port);
    if (err) {
        bpf_printk("read sockaddr ipv4 port failed.\n");
        return 0;
    }
    valEvnt->rport = bpf_ntohs(rport);
    return 0;
}

// trace sendto(a,b,c,d, const struct sockaddr* dest_addr, f) exit
SEC("tracepoint/syscalls/sys_exit_sendto")
int tracepoint__syscalls__sys_exit_sendto(struct trace_event_raw_sys_exit *ctx){
    if (ctx->id != __NR_sendto) return 0;
    int err = 0;
    struct sendto_evnt *evnt;
    // get pid
    pid_t task_pid = bpf_get_current_pid_tgid();
    // chekc if enter evnt has rec
    evnt = bpf_map_lookup_elem(&sendto_maps, &task_pid);
    if (!evnt) {
        return 0;
    }
    // update retval
    evnt->retval = ctx->ret;
    // submit
    err = bpf_perf_event_output(ctx, &sto_u_events, BPF_F_CURRENT_CPU, evnt, sizeof(*evnt));
    if (err){
        bpf_printk("perf_event_output failed.\n");
        return 0;
    }
    // cleanup , delete event
    err = bpf_map_delete_elem(&sendto_maps, &task_pid);
    if (err) {
        return 0;
    }
    return 0;
}


// trace recvfrom(a,b,c,d, struct sockaddr* from, f) enter
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int tracepoint__syscalls__sys_enter_recvfrom(struct trace_event_raw_sys_enter *ctx){
    if (ctx -> id != __NR_recvfrom) return 0;
    int err = 0;
    struct recvfrom_evnt nEvnt = { 0 };
    struct recvfrom_evnt *valEvnt;

    // get pid, task struct
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    pid_t task_pid;
    task_pid = bpf_get_current_pid_tgid();

    err = bpf_map_update_elem(&recvfrom_maps, &task_pid, &nEvnt, BPF_ANY);
    if (err) {
        return 0;
    }

    valEvnt = bpf_map_lookup_elem(&recvfrom_maps, &task_pid);
    if (!valEvnt) {
        // create failed, error
        return 0;
    }

    valEvnt->pid=task_pid;

    // get comm
    err = bpf_get_current_comm(valEvnt->comm, sizeof(valEvnt->comm));
    if (err) {
        bpf_printk("read executable name from task struct comm field failed\n");
        return 0; // always return 0 to prevent from hanging around.
    }

    // get ppid and uid and uts namespace nodename
    valEvnt->ppid = BPF_CORE_READ(task, real_parent, pid);
    valEvnt->uid = BPF_CORE_READ(task, real_cred, uid.val);

    char *uts_name = BPF_CORE_READ(task, nsproxy, uts_ns, name.nodename);
    if (uts_name) {
        err = bpf_probe_read(&valEvnt->uts_name, sizeof(valEvnt->uts_name), uts_name);
        if (err){
            bpf_printk("read uts_name failed.\n");
            return 0;
        }
    }

    struct sockaddr *from_addr = (struct sockaddr *) ctx->args[4];
    // check if ipv4
    sa_family_t fam;
    err = bpf_probe_read(&fam, sizeof(from_addr->sa_family), &from_addr->sa_family);
    if (err) {
        bpf_printk("read sockaddr family failed.\n");
        return 0;
    }
    if (fam != AF_INET) {
        // only support IPv4 currently
        return 0;
    }
    valEvnt->family = fam;
    // record saddr
    // directly cast, check below link for details
    // https://stackoverflow.com/questions/1276294/getting-ipv4-address-from-a-sockaddr-structure/1276307
    struct sockaddr_in *sin = (struct sockaddr_in *) from_addr;
    err = bpf_probe_read(&valEvnt->saddr, sizeof(sin->sin_addr.s_addr), &sin->sin_addr.s_addr);
    if (err) {
        bpf_printk("read sockaddr ipv4 address failed.\n");
        return 0;
    }

    u32 sport = 0;
    err = bpf_probe_read(&sport, sizeof(sin->sin_port), &sin->sin_port);
    if (err) {
        bpf_printk("read sockaddr ipv4 port failed.\n");
        return 0;
    }
    valEvnt->sport = bpf_ntohs(sport);
    return 0;
}


// trace recvfrom(a,b,c,d, struct sockaddr* from, f) exit
SEC("tracepoint/syscalls/sys_exit_recvfrom")
int tracepoint__syscalls__sys_exit_recvfrom(struct trace_event_raw_sys_exit *ctx){
    if (ctx->id != __NR_recvfrom) return 0;
    int err = 0;
    struct recvfrom_evnt *evnt;
    // get pid
    pid_t task_pid = bpf_get_current_pid_tgid();
    // chekc if enter evnt has rec
    evnt = bpf_map_lookup_elem(&recvfrom_maps, &task_pid);
    if (!evnt) {
        return 0;
    }
    // update retval
    evnt->retval = ctx->ret;
    // submit
    err = bpf_perf_event_output(ctx, &rfrom_u_events, BPF_F_CURRENT_CPU, evnt, sizeof(*evnt));
    if (err){
        bpf_printk("perf_event_output failed.\n");
        return 0;
    }
    // cleanup , delete event
    err = bpf_map_delete_elem(&recvfrom_maps, &task_pid);
    if (err) {
        return 0;
    }
    return 0;
}
