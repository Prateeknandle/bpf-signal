#### Generate vmlinux.h

run `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h` in `ebpf_src` dir.

#### Generate object file

execute `clang -g -O2 -target bpf -c ebpf_src/agent.c -o agent.o`

#### Generate binary

execute `go build -o main`

#### Run agent

execute `sudo ./main`



#### Note

We are not tracing if signal sent is not a kill signal. 

Kill signals that we are tracing (we can add more if needed):

SIGKILL	9	Immediate, uncatchable termination.
SIGTERM	15	Graceful termination request.
SIGQUIT	3	Terminates and produces a core dump.
SIGABRT	6	Abort signal, typically from abort().
SIGHUP	1	Can be used to terminate or reload daemons.
SIGINT	2	Sent by Ctrl+C to terminate foreground processes.

SIGSTOP	19	Immediately stops a process (uncatchable).
SIGTSTP	20	Stops a process (can be resumed, sent via Ctrl+Z).
SIGTTIN	21	Stops a background process trying to read input.
SIGTTOU	22	Stops a background process trying to write output.
