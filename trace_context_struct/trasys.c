#include"vmlinux.h"
#include<bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

struct trace_syscalls_enter_execve {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int syscall_nr;
    char *filename;
    const* char* argv;
    const* char* envp;
};

SEC("tp/syscalls/sys_enter_execve")
int hellobpf(struct trace_syscalls_enter_execve *ctx) {
    bpf_printk("exec enter call filename=%s! \n", ctx->filename);
    return 0;
}



