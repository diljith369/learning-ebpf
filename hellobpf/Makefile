EBPF_OBJ = hellobpf.o
VMLINUX_H = vmlinux.h
SKEL = userspace.skel.h
USERSPACE_OBJ = userspace.o


.PHONY: ebpf vmlinux skeleton userspace clean

ebpf: $(EBPF_OBJ)

$(EBPF_OBJ): hellobpf.c
	sudo clang -O2 -target bpf -c hellobpf.c -o hellobpf.o

vmlinux: $(VMLINUX_H)

$(VMLINUX_H): 
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

skeleton: $(EBPF_OBJ)
	sudo bpftool gen skeleton hellobpf.o name userspace > userspace.skel.h

userspace: usrspace.c $(SKEL)
	clang usrspace.c -lbpf -o userspace.o
clean:
	rm -f $(EBPF_OBJ) $(VMLINUX_H) $(SKEL) $(USERSPACE_OBJ)