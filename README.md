#### Generate vmlinux.h

run `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h` in `ebpf_src` dir.

#### Generate object file

execute `clang -g -O2 -target bpf -c ebpf_src/agent.c -o agent.o`

#### Generate binary

execute `go build -o main`

#### Run agent

execute `sudo ./main`



#### Note

We are not tracing if signal is zero, because it's not a kill attempt, I am considerin signal 23 as a kill attempt becuase it does pause the process and might kill it eventually.