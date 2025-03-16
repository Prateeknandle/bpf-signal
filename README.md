#### Generate vmlinux.h

run `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h` in `ebpf_src` dir.

#### Generate object file

execute `clang -g -O2 -target bpf -c ebpf_src/agent.c -o agent.o`

#### Generate binary

execute `go build -o main`

#### Run agent

execute `sudo ./main`