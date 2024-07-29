#include<linux/bpf.h>
#include<bpf/bpf_helpers.h>


char  _license[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_execve")
int hellobpf(void *ctx){

bpf_printk("exec enter call received\n");
return 0;

}

