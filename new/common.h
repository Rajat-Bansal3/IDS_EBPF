#ifndef COMMON_H
#define COMMON_H

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <bcc/proto.h>
#include <net/sock.h>
#include <helper/helper.h>
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


BPF_HASH(WHITELIST_USERS, u32, u8);      
BPF_HASH(WHITELIST_PROCS, u32, u8);      
BPF_HASH(WHITELIST_PATHS, u64, u8);      
BPF_HASH(WHITELIST_IPS, u32, u8);        
BPF_HASH(WHITELIST_PORTS, u16, u8);      

static __always_inline bool is_whitelisted(const char *filename, u32 dst_ip, u16 dst_port) {
    u32 uid = bpf_get_current_uid_gid();
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    if (WHITELIST_USERS.lookup(&uid)) {
        return true;
    }

    u32 comm_hash = bpf_hash_str(comm);
    if (WHITELIST_PROCS.lookup(&comm_hash)) {
        return true;
    }

    if (filename && filename[0] != '\0') {
        char normalized[MAX_PATH_LEN];
        
        normalize_path(filename, normalized);
        u64 full_hash = bpf_hash_str(normalized);
        if (WHITELIST_PATHS.lookup(&full_hash)) {
            return true;
        }

        const char *base = get_basename(normalized);
        u64 base_hash = bpf_hash_str(base);
        if (WHITELIST_PATHS.lookup(&base_hash)) {
            return true;
        }
    }

    if (dst_ip != 0) {
        u32 net_ip = bpf_htonl(dst_ip);
        if (WHITELIST_IPS.lookup(&net_ip)) {
            return true;
        }
    }

    if (dst_port != 0) {
        u16 net_port = bpf_htons(dst_port);
        if (WHITELIST_PORTS.lookup(&net_port)) {
            return true;
        }
    }

    return false;
}

#endif

