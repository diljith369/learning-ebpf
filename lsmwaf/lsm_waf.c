#include "vmlinux.h"
#include<bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/errno.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_FILENAME_LEN 50
#define WEB_USER 33

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2);
    __type(key, char[MAX_FILENAME_LEN]);
    __type(value, sizeof(u32));

} allowed_bins SEC(".maps") ;


SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check_security, struct linux_binprm *bprm)
 {
    
    
    u32 cred_uid = -1;
    char current_comm[MAX_FILENAME_LEN] = {0};
    bpf_probe_read_kernel(&cred_uid, sizeof(cred_uid),&bprm->cred->uid.val);
    bpf_probe_read_kernel_str(current_comm, sizeof(current_comm), bprm->filename);
    
    if(cred_uid == WEB_USER) 
    {
            
        bpf_printk("Current command is %s \n", current_comm);
        int *allowed = bpf_map_lookup_elem(&allowed_bins, &current_comm);     
        if(allowed) {
                            return 0;
        }
        else {
            
                bpf_printk("blocked command  %s: \n", current_comm);
                return -1;  // block the execution
        }
    }
   
    return  0;
}
