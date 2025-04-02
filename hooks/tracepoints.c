#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <bcc/proto.h>
#include <net/sock.h>
struct ids_event_t {
    u32 pid;
    u32 ppid;
    u64 timestamp;
    char comm[TASK_COMM_LEN];
    char syscall[32];
    char filename[128];
    int signal;
    int new_state;
    u32 uid;
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
};

BPF_PERF_OUTPUT(ids_events);

//TRACEPOINT_PROBE(syscalls, syscall_name) { 
//    struct ids_event_t event = {}; 
//    event.pid = bpf_get_current_pid_tgid() >> 32; 
//    struct task_struct *task = (struct task_struct *)bpf_get_current_task(); 
//    bpf_probe_read(&event.ppid, sizeof(event.ppid), &task->real_parent->tgid); 
//    event.timestamp = bpf_ktime_get_ns(); 
//    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF; 
//    event.gid = (bpf_get_current_uid_gid() >> 32) & 0xFFFFFFFF; 
//    bpf_get_current_comm(&event.comm, sizeof(event.comm)); 
//    __builtin_memcpy(event.syscall, #syscall_name, sizeof(#syscall_name)); 
//    ids_events.perf_submit(args, &event, sizeof(event)); 
//    return 0; 
//}

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
    ids_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_kill) {
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
    ids_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {  
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
    __builtin_memcpy(event.syscall, "sys_enter_connect", sizeof("sys_enter_connect"));  
    ids_events.perf_submit(args, &event, sizeof(event));  
    return 0;  
}

TRACEPOINT_PROBE(syscalls, sys_enter_bind) {
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
    bpf_get_current_comm(&event.comm, sizeof(event.comm));  
    event.signal = 0;                               
    event.new_state = 0;
    __builtin_memcpy(event.syscall, "sys_enter_openat", sizeof("sys_enter_openat"));  
    ids_events.perf_submit(args, &event, sizeof(event));  
    return 0;  
}
TRACEPOINT_PROBE(syscalls, sys_enter_socket) {
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
    __builtin_memcpy(event.syscall, "sys_enter_socket", sizeof("sys_enter_socker"));  
    ids_events.perf_submit(args, &event, sizeof(event));  
    return 0;  
}

