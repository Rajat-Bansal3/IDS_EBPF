#include <common.h>

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct ids_event_t event = {};
     __builtin_memset(&event, 0, sizeof(event));
    event.pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel(&event.ppid, sizeof(event.ppid), &task->real_parent->tgid);
    event.timestamp = bpf_ktime_get_ns();
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.signal = 0;       
    event.new_state = 0; 
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    __builtin_memcpy(event.syscall, "sys_enter_execve", sizeof("sys_enter_execve"));

    bpf_probe_read_user_str(event.filename, sizeof(event.filename), (void *)args->filename);
    if (is_whitelisted(event.filename, 0, 0)) return 0;
    ids_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_kill) {
    if (is_whitelisted(0, 0, 0)) return 0;
    struct ids_event_t event = {};
     __builtin_memset(&event, 0, sizeof(event));
    event.pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel(&event.ppid, sizeof(event.ppid), &task->real_parent->tgid);
    event.new_state = 0;
    event.timestamp = bpf_ktime_get_ns();
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    __builtin_memcpy(event.syscall, "sys_enter_kill", sizeof("sys_enter_kill"));

    bpf_probe_read(&event.signal, sizeof(event.signal), &args->sig);
    ids_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(sock, inet_sock_set_state) {
    struct ids_event_t event = {};
     __builtin_memset(&event, 0, sizeof(event));
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.timestamp = bpf_ktime_get_ns();
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    __builtin_memcpy(event.syscall, "inet_sock_set_state", sizeof("inet_sock_set_state"));
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel(&event.ppid, sizeof(event.ppid), &task->real_parent->tgid);
    event.signal = 0;
    event.new_state = args->newstate;
    event.src_ip = bpf_ntohl(*(u32 *)args->saddr);
    event.dst_ip = bpf_ntohl(*(u32 *)args->daddr);
    bpf_probe_read(&event.src_port, sizeof(event.src_port), &args->sport);
    bpf_probe_read(&event.dst_port, sizeof(event.dst_port), &args->dport);
    if (is_whitelisted(0, event.dst_ip, event.dst_port)) return 0;
    ids_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct ids_event_t event = {};
    struct sockaddr *addr;
    bpf_probe_read_user(&addr, sizeof(addr), &args->uservaddr);

    if (addr->sa_family != AF_INET) return 0;

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel(&event.ppid, sizeof(event.ppid), &task->real_parent->tgid);
    struct sockaddr_in sin;
    bpf_probe_read_user(&sin, sizeof(sin), addr);
    event.dst_ip = bpf_ntohl(sin.sin_addr.s_addr);  
    event.dst_port = bpf_ntohs(sin.sin_port);       
    event.timestamp = bpf_ktime_get_ns();

    if (is_whitelisted(NULL, event.dst_ip, event.dst_port)) return 0;

    __builtin_memcpy(event.syscall, "sys_enter_connect", sizeof("sys_enter_connect"));
    ids_events.perf_submit(args, &event, sizeof(event));
    
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_bind) {
    if (is_whitelisted(0, 0, 0)) return 0;
    struct ids_event_t event = {};  
     __builtin_memset(&event, 0, sizeof(event));
    event.pid = bpf_get_current_pid_tgid() >> 32;  
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();  
    bpf_probe_read_kernel(&event.ppid, sizeof(event.ppid), &task->real_parent->tgid);
    event.timestamp = bpf_ktime_get_ns();  
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;  
    bpf_get_current_comm(&event.comm, sizeof(event.comm));  
    event.signal = 0;                               
    event.new_state = 0;
    __builtin_memcpy(event.syscall, "sys_enter_bind", sizeof("sys_enter_bind"));  
    ids_events.perf_submit(args, &event, sizeof(event));  
    return 0;  
}
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct ids_event_t event = {};  
     __builtin_memset(&event, 0, sizeof(event));
    event.pid = bpf_get_current_pid_tgid() >> 32;  
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();  
    bpf_probe_read_kernel(&event.ppid, sizeof(event.ppid), &task->real_parent->tgid);
    event.timestamp = bpf_ktime_get_ns();  
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;  
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), args->filename);
    if (is_whitelisted(event.filename, 0, 0)) return 0;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));  
    event.signal = 0;                               
    event.new_state = 0;
    __builtin_memcpy(event.syscall, "sys_enter_openat", sizeof("sys_enter_openat"));  
    ids_events.perf_submit(args, &event, sizeof(event));  
    return 0;  
}
TRACEPOINT_PROBE(syscalls, sys_enter_socket) {
    if (is_whitelisted(0, 0, 0)) return 0;
    struct ids_event_t event = {};  
     __builtin_memset(&event, 0, sizeof(event));
    event.pid = bpf_get_current_pid_tgid() >> 32;  
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();  
    bpf_probe_read_kernel(&event.ppid, sizeof(event.ppid), &task->real_parent->tgid);
    event.timestamp = bpf_ktime_get_ns();  
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;  
    bpf_get_current_comm(&event.comm, sizeof(event.comm));  
    event.signal = 0;                               
    event.new_state = 0;
    __builtin_memcpy(event.syscall, "sys_enter_socket", sizeof("sys_enter_socket"));  
    ids_events.perf_submit(args, &event, sizeof(event));  
    return 0;  
}

