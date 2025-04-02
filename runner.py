from bcc import BPF
from pathlib import Path

bpf_source = Path("./ebpf-probe.c").read_text()
bpf = BPF(text=bpf_source)

def process_event_clone(cpu , data , size):
    event = bpf["clone_events"].event(data)
    print(f"Process {event.comm.decode()} (PID: {event.pid}, PPID : {event.ppid}) called sys clone")

def process_event_openat2(cpu , data , size):
    event = bpf["openat2_events"].event(data)
    print(f"[{event.timestamp/1e9:.6f}Process {event.comm.decode()}(PID: {event.pid})] opened file: {event.filename}")

bpf['clone_events'].open_perf_buffer(process_event_clone)
bpf['openat2_events'].open_perf_buffer(process_event_openat2)

while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        break

