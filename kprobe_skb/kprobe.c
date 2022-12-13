// +build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") kprobe_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,
};

// SEC("kprobe/sys_execve")
// int kprobe_execve() {
// 	u32 key     = 0;
// 	u64 initval = 1, *valp;

// 	valp = bpf_map_lookup_elem(&kprobe_map, &key);
// 	if (!valp) {
// 		bpf_map_update_elem(&kprobe_map, &key, &initval, BPF_ANY);
// 		return 0;
// 	}
// 	__sync_fetch_and_add(valp, 1);

// 	return 0;
// }


// inline int do_trace(struct pt_regs *ctx, struct sk_buff *skb, const char *func_name) {
//     GET_CFG();
//     GET_EVENT_BUF();

//     if (!do_trace_skb(event, cfg, ctx, skb)) return 0;

//     if (!filter_callstack(cfg))
//         set_callstack(event, ctx);

//     bpf_strncpy(event->func_name, func_name, FUNCNAME_MAX_LEN);
//     bpf_perf_event_output(ctx, &skbtracer_event, BPF_F_CURRENT_CPU, event,
//                           sizeof(struct event_t));

//     return 0;
// }


SEC("kprobe/netif_rx")
int k_netif_rx(struct pt_regs *ctx) {
	u32 key     = 0;
	u64 initval = 1, *valp;

	valp = bpf_map_lookup_elem(&kprobe_map, &key);
	if (!valp) {
		bpf_map_update_elem(&kprobe_map, &key, &initval, BPF_ANY);
		return 0;
	}
	__sync_fetch_and_add(valp, 1);


	return 0;
    // struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    // return do_trace(ctx, skb, "netif_rx");
}
