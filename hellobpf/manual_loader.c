#include<stdio.h>
#include<unistd.h>
#include<bpf/libbpf.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <poll.h>

int main(int argc, char **argv) {

     struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return 1;
    }
    
    struct bpf_object *obj;
    int prog_fd;
    struct bpf_link *link;


    obj = bpf_object__open_file("bpfhello.o", NULL);
    if(libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR : opening BPF object file failed\n");
        return 1;
    }

    int ret = bpf_object__load(obj);
    if (ret != 0) {
        fprintf(stderr, "ERROR: loading BPF object file failed (error code: %d)\n", ret);
        return 1;
    
    
    }

    struct  bpf_program *prog = bpf_object__find_program_by_name(obj, "hellobpf");
    if(!prog) {
        fprintf(stderr, "ERROR: finding BPF program failed\n");
        return 1;
    }

    prog_fd = bpf_program__fd(prog);

    link = bpf_program__attach_tracepoint(prog, "syscalls", "sys_enter_execve");
    if (!link) {
        perror("bpf_program__attach_tracepoint");
        fprintf(stderr, "ERROR: attaching BPF program to tracepoint failed\n");
        bpf_object__close(obj);
        return 1;
    }

    printf("Successfully loaded and attached BPF program\n");

     while (1) {
        sleep(1);
    }

    return 0;
}