#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<sys/resource.h>

#include"loader.skel.h"

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
    struct userspace *skel = userspace__open();
    userspace__load(skel);
    userspace__attach(skel);

    for(;;) {
        sleep(1);
    }

}