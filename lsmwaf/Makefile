EBPF_OBJ = lsm_waf.o
EBPF_SRC = lsm_waf.c
VMLINUX_H = vmlinux.h
SKEL_H = wafloader.skel.h
USERSPACE_OBJ = loader.o
USERSPACE_SRC = loader.c
MAN_USERSPACE_SRC = waf_loader.c
MAN_USERSPACE_OBJ = waf_loader.o


.PHONY: ebpf vmlinux skeleton loader clean

ebpf: $(EBPF_OBJ)

$(EBPF_OBJ): $(EBPF_SRC)
	sudo clang -O2 -target bpf -g -c $(EBPF_SRC) -o $(EBPF_OBJ)

vmlinux: $(VMLINUX_H)

$(VMLINUX_H):
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

full_loader: $(EBPF_OBJ)
	sudo bpftool gen skeleton $(EBPF_OBJ) name loader > $(SKEL_H)
	clang $(USERSPACE_SRC) -lbpf -o $(USERSPACE_OBJ)

skeleton: $(EBPF_OBJ)
	sudo bpftool gen skeleton $(EBPF_OBJ) name loader > $(SKEL_H)

loader: $(USERSPACE_SRC) $(SKEL)
	clang $(USERSPACE_SRC) -lbpf -o $(USERSPACE_OBJ)

manual: $(MAN_USERSPACE_SRC) $(SKEL)
	clang $(MAN_USERSPACE_SRC) -lbpf -o $(MAN_USERSPACE_OBJ)
	
delebpf:
	rm -f $(EBPF_OBJ)

runm: $(EBPF_OBJ) $(MAN_USERSPACE_SRC) $(SKEL) $(MAN_USERSPACE_OBJ)
	sudo bpftool gen skeleton $(EBPF_OBJ) name loader > $(SKEL_H)
	clang $(USERSPACE_SRC) -lbpf -o $(USERSPACE_OBJ)
	clang $(MAN_USERSPACE_SRC) -lbpf -o $(MAN_USERSPACE_OBJ)
	sudo ./$(MAN_USERSPACE_OBJ)
clean:
	rm -f $(EBPF_OBJ) $(SKEL) $(USERSPACE_OBJ) $(MAN_USERSPACE_OBJ)
