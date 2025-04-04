from bcc import BPF
import ctypes as ct
import socket
import struct
from time import strftime, localtime
from pathlib import Path
class ids_event_t(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("ppid", ct.c_uint),
        ("timestamp", ct.c_ulonglong),
        ("comm", ct.c_char * 16),          
        ("syscall", ct.c_char * 32),
        ("filename", ct.c_char * 255),    
        ("sockfd", ct.c_int),
        ("signal", ct.c_int),
        ("new_state", ct.c_int),
        ("uid", ct.c_uint),
        ("gid", ct.c_uint),
        ("src_ip", ct.c_uint),
        ("dst_ip", ct.c_uint),
        ("src_port", ct.c_ushort),
        ("dst_port", ct.c_ushort),
    ]
def handle_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(ids_event_t)).contents
    
    ts = strftime("%H:%M:%S", localtime(event.timestamp / 1e9))
    
    def int_to_ip(ip):
        return socket.inet_ntoa(struct.pack("!I", ip)) if ip != 0 else "N/A"
    
    base = f"{ts} [{event.comm.decode()}] PID:{event.pid} UID:{event.uid} Syscall:{event.syscall.decode()}"
    
    extras = []
    if event.filename.decode().strip('\x00'):
        extras.append(f"File: {event.filename.decode()}")
    if event.signal != 0:
        extras.append(f"Signal: {event.signal}")
    if event.new_state != 0:
        extras.append(f"NewState: {event.new_state}")
    if event.src_ip or event.dst_ip:
        extras.append(f"Network: {int_to_ip(event.src_ip)}:{socket.ntohs(event.src_port)} → {int_to_ip(event.dst_ip)}:{socket.ntohs(event.dst_port)}")
    
    print(f"{base}{' | ' if extras else ''}{' | '.join(extras)}")

if __name__ == "__main__":
    header = Path("common.h").read_text()
    tracepoints = Path("./hooks/tracepoints.c").read_text()
    probes = Path("./hooks/probes.c").read_text()
    print(header)
    combined = header + tracepoints + probes
    bpf = BPF(text=combined)
    
    bpf["ids_events"].open_perf_buffer(handle_event)
    
    print("Tracing system events... Ctrl+C to exit")
    
    try:
        while True:
            bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nDetaching...")
