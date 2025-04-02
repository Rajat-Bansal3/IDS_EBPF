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

