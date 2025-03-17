#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/errno.h>

#define SIGKILL 9
#define SIGTERM 15
#define SIGQUIT 3
#define SIGABRT 6
#define SIGHUP 1
#define SIGINT 2
#define SIGSTOP 19
#define SIGTSTP 20
#define SIGTTIN 21
#define SIGTTOU 22

struct event {
    u32 src_pid;
    u32 target_pid;
    int sig;
    int blocked;
};

// used to store the agent pid and send from userspace to kernelspace
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} agent_pid_map SEC(".maps");

// used for sending kill event info to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 1024);
} events SEC(".maps");

// using lsm hook since they are prefered in context of security enforcement and access control
// and also have low overhead compratively to kprobes/kretprobes.
SEC("lsm/task_kill")
int BPF_PROG(task_kill, struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred)
{
    struct event evt = {};
    evt.src_pid = bpf_get_current_pid_tgid() >> 32;
    evt.target_pid = p->pid;             // fetching target pid from task_struct provided by lsm hook
    evt.sig = sig;                       // sig provided by lsm hook
    evt.blocked = 0;

    u32 key = 0;
    u32 *agent_pid_ptr = bpf_map_lookup_elem(&agent_pid_map, &key); // fetching agent pid


    // since we only needed to trace kill attempts by other processes (as mentioned in the problem statement)
    // therefore skipping tracing if process is killed by itself
    // also confirmed with ashish about skipping blocking agent killed by itself for eg - ctrl + c
    if (evt.src_pid == evt.target_pid) {
        return 0;
    }

    // adding condition here specifically to trace if signal is of a kill attempt
    if (agent_pid_ptr && *agent_pid_ptr == evt.target_pid && (sig == SIGKILL || sig == SIGTERM || sig == SIGQUIT || sig == SIGABRT || sig == SIGHUP || sig == SIGINT || sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTIN) ) {
        evt.blocked = 1;
        // signal was not asked but just tracing for my understanding
        bpf_printk("Kill attempt targeting agent detected: source PID %d attempting to kill agent PID %d with signal %d",
            evt.src_pid, evt.target_pid, evt.sig);
        bpf_printk("Kill attempt blocked successfully");
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        return -EPERM; // block the kill attempt for agent
    }
    
    // adding condition here specifically to trace if signal is of a kill attempt
    if (sig == SIGKILL || sig == SIGTERM || sig == SIGQUIT || sig == SIGABRT || sig == SIGHUP || sig == SIGINT || sig == SIGSTOP || sig == SIGTSTP || sig == SIGTTIN || sig == SIGTTIN) {
        bpf_printk("Kill attempt detected: source PID %d attempting to kill target PID %d with signal %d",
            evt.src_pid, evt.target_pid, evt.sig);

        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    }
    
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
