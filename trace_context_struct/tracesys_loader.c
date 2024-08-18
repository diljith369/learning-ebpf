#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<sys/resource.h>

#include"tracesysloader.skel.h"

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

    //open
    //load
    //attach
    struct tracesysloader *skel = tracesysloader__open();
    tracesysloader__load(skel);
    tracesysloader__attach(skel);

     while (1) {
        sleep(1);
    }

}