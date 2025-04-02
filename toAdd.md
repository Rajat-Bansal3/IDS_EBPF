
Hook Type	Syscall/Function					Purpose
Tracepoint	syscalls/sys_enter_execve				Track binary execution (e.g., execve).
		syscalls/sys_enter_connect				Monitor outbound network connections (IPv4/IPv6).
		syscalls/sys_enter_bind					Detect unauthorized socket binding (e.g., rogue services).
		syscalls/sys_enter_openat				Monitor file access (e.g., /etc/shadow).
		syscalls/sys_enter_kill					Track signals sent to processes (e.g., SIGKILL).
		syscalls/sys_enter_socket				Audit socket creation (e.g., AF_INET/SOCK_RAW).
		syscalls/sys_enter_clone/syscalls/sys_enter_fork	Monitor process/thread creation (e.g., fork bombs).
		sock:inet_sock_set_state				track TCP state changes (e.g., ESTABLISHED, SYN_SENT).
Kprobe		__x64_sys_ptrace					Detect process debugging/tampering (e.g., PTRACE_ATTACH).
		__x64_sys_mprotect					Flag memory protection changes (e.g., PROT_EXEC for shellcode).
		__x64_sys_openat2					Monitor newer openat2 syscall (if tracepoint unavailable).
Kretprobe	__x64_sys_openat					Check return values (e.g., file descriptors for sensitive files).
LSM Hooks	file_permission						Intercept file access checks (e.g., block writes to sensitive paths).
		bprm_check_security					Validate executable loading (e.g., detect malicious scripts).
Fentry		security_socket_connect					Modern alternative to kprobe for socket connections (lower overhead).
Socket Filter	BPF_PROG_TYPE_SOCKET_FILTER				Inspect packet payloads (e.g., detect exploi
