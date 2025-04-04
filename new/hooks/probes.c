#include <common.h>

int kprobe____x64_sys_ptrace(struct pt_regs *ctx, 
                            int request, 
                            pid_t pid, 
                            void __user *addr, 
                            void __user *data) {
    struct ids_event_t event = {};
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel(&event.ppid, sizeof(event.ppid), &task->real_parent->tgid);
    event.timestamp = bpf_ktime_get_ns();
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    u32 *is_admin = admin_users.lookup(&event.uid);
    if (is_admin) {
        return 0;          
    }
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    __builtin_memcpy(event.syscall, "ptrace", sizeof("ptrace"));

    event.signal = request;  
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), 
                          (void *)data);

    ids_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

int kprobe____x64_sys_mprotect(struct pt_regs *ctx,
                             unsigned long start,
                             size_t len,
                             unsigned long prot) {
    struct ids_event_t event = {};
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel(&event.ppid, sizeof(event.ppid), &task->real_parent->tgid);
    event.timestamp = bpf_ktime_get_ns();
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    u32 *is_admin = admin_users.lookup(&event.uid);
    if (is_admin) {
        return 0;          
    }

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    __builtin_memcpy(event.syscall, "mprotect", sizeof("mprotect"));

    event.src_ip = start;  
    event.dst_ip = len;   
    event.src_port = prot;

    ids_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

int kprobe____x64_sys_openat2(struct pt_regs *ctx,
                            int dfd,
                            const char __user *filename,
                            struct open_how *how,
                            size_t size) {
    struct ids_event_t event = {};
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel(&event.ppid, sizeof(event.ppid), &task->real_parent->tgid);
    event.timestamp = bpf_ktime_get_ns();
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    u32 *is_admin = admin_users.lookup(&event.uid);
    if (is_admin) {
        return 0;          
    }

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    __builtin_memcpy(event.syscall, "openat2", sizeof("openat2"));

    bpf_probe_read_user_str(event.filename, sizeof(event.filename), filename);
    event.signal = how->flags;

    ids_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
