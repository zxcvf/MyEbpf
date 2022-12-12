// +build ignore

#include "common.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") kprobe_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,
};


char filename[20];

SEC("kprobe/sys_openat")
int kprobe_openat(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("pid:%d, 123123",pid);
	// char filename[32];
	// const char *fp = (char *)PT_REGS_PARM2(ctx);
	// PT_REGS_PARM2需要指定target，在main.go中，继续修改第19行  (--target=amd64)
	// long err = bpf_probe_read_user_str(&filename, sizeof(filename), fp);
	// bpf_printk("pid:%d,filename:%s,err:%ld",pid,filename,err);
	return 0;
	// u32 key     = 0;
	// u64 initval = 1, *valp;

	// valp = bpf_map_lookup_elem(&kprobe_map, &key);
	// if (!valp) {
	// 	bpf_map_update_elem(&kprobe_map, &key, &initval, BPF_ANY);
	// 	return 0;
	// }
	// __sync_fetch_and_add(valp, 1);

	// return 0;
}
