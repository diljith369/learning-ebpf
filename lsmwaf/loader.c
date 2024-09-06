#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<sys/resource.h>

#include"wafloader.skel.h"


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
    struct loader *skel = loader__open();
    loader__load(skel);
    loader__attach(skel);



     while (1) {
       sleep(2);
    }

}
