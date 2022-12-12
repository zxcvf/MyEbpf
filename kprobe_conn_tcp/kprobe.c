// +build ignore

#include "common.h"
#include "vmlinux.h"

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("kprobe/tcp_set_state")
int kprobe__tcp_set_state(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    bpf_printk(">");
	return 0;
}
