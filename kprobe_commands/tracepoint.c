// +build ignore

// 导入
#include "common.h"
#include <bpf/bpf_helpers.h>

// license
char __license[] SEC("license") = "Dual MIT/GPL";

// bpf map
// struct bpf_map_def SEC("maps") event_map = {
// 	.type        = BPF_MAP_TYPE_ARRAY,
// 	.key_size    = sizeof(u32),
// 	.value_size  = sizeof(u64),
// 	.max_entries = 1,
// };

// struct bpf_map_def SEC("maps") event_map = {
// 	.type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
// 	.key_size    = sizeof(u32),
// 	.value_size  = sizeof(u64),
// };
// https://zhuanlan.zhihu.com/p/561601231 map解惑
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} event_map SEC(".maps");


// 用来传递的struct
#define FNAME_LEN 32
struct exec_data_t {
	u32 pid;
	u8 fname[FNAME_LEN];  // u8 无符号字符串 char   8位刚好1个byte
	u8 comm[FNAME_LEN];
};

struct execve_entry_args_t  {
	u64 _unused;
	u64 _unused2;

	const char* filename;
	const char* const* argv;
	const char* const* envp;
};

#define LAST_32_BITS(x) x & 0xFFFFFFFF
#define FIRST_32_BITS(x) x >> 32

// 1. 附着系统函数
SEC("tracepoint/syscalls/sys_enter_execve")
int enter_execve(struct execve_entry_args_t *args) {
	// 2. 确定参数 cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
	// name: sys_enter_execve
	// ID: 692
	// format:
	//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
	//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
	//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
	//         field:int common_pid;   offset:4;       size:4; signed:1;

	//         field:int __syscall_nr; offset:8;       size:4; signed:1;
	//         field:const char * filename;    offset:16;      size:8; signed:0;
	//         field:const char *const * argv; offset:24;      size:8; signed:0;
	//         field:const char *const * envp; offset:32;      size:8; signed:0;
	//         offset 单位是 1 bytes,    16 bytes = 128 bit 所以定义两 uint64

	struct exec_data_t exec_data = {};

	u64 pid_tgid;
	pid_tgid = bpf_get_current_pid_tgid();
	exec_data.pid = LAST_32_BITS(pid_tgid);

	// kprobe 将不安全的内核地址*unsafeptr 复制到exec_data.fname
	bpf_probe_read_user_str(exec_data.fname, sizeof(exec_data.fname), args->filename);

	// 用当前进程名字填充第一个参数地址
	bpf_get_current_comm(exec_data.comm, sizeof(exec_data.comm));

	// output至用户空间 比bpf_printk有更好的性能
	bpf_perf_event_output(args, &event_map, BPF_F_CURRENT_CPU, &exec_data, sizeof(exec_data));

	// args->argv 直接取会因为地址不安全报错 需要用辅助函数提取 
	// bpf_printk("bash: filename: %s", args->filename);
	return 0;
}
