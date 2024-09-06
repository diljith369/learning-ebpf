#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "wafloader.skel.h"

#define MAX_FILENAME_LEN 50
#define COMM_LEN 16

static void setmemoryforuserspace() {
    struct rlimit newlimit = {
        .rlim_cur  = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if(setrlimit(RLIMIT_MEMLOCK, &newlimit)) {
        fprintf(stderr, "error in increasing memory for userspace app! \n");
    }

}


int main() {

    setmemoryforuserspace();    
    struct loader *skel = loader__open();
    loader__load(skel);
    loader__attach(skel);
    printf("eBPF/LSM WAF hook loaded\n");

    int map_allowed_bin_fd = bpf_map__fd(skel->maps.allowed_bins);
    printf("Map FD: %d\n", map_allowed_bin_fd);
    if (map_allowed_bin_fd < 0) {
        fprintf(stderr, "ERROR: finding allowed map in skeleton object file failed\n");
        return 1;
    }
    
    int allowed= 1;
    const char *allowed_fnames[] = {"/usr/bin/ping","/bin/sh"};

    for (int i = 0; i < 2; i++) {
         char key[MAX_FILENAME_LEN] = {0};
         strncpy(key, allowed_fnames[i], MAX_FILENAME_LEN- 1);
         key[MAX_FILENAME_LEN - 1] = '\0';
         printf("%s\n", key);
         //printf("key[12 -]: %02x %02x %02x %02x %02x %02x %02x %02x\n", key[12], key[13], key[14], key[15],key[16], key[17], key[18], key[19]);
        int ret = bpf_map_update_elem(map_allowed_bin_fd, key, &allowed, BPF_ANY);
        if (ret !=0) {

            fprintf(stderr, "ERROR: adding to not_allowed list failed\n");
            return 1;
        }
    }
   
    
    
    printf("WAF Hook in action. Press enter to exit.\n");
    getchar();

     return 0;

}
