apt install clang llvm
export BPF_CLANG=clang

查看某操作的系统调用
$ strace cmd          // strace cat README.txt
bpf 辅助函数
https://www.man7.org/linux/man-pages/man7/bpf-helpers.7.html


----------------
编译过程

// kprobe
cd kprobe
go generate 
go build

-----------------
重要工具
perf
perf 是Linux的一款性能分析工具，能够进行函数级和指令级的热点查找，可以用来分析程序中热点函数的CPU占用率，从而定位性能瓶颈。
$perf list 或者 $perf list 'syscalls:*' 确认系统函数

-----------------
重要文档
ebpf库
https://github.com/cilium/ebpf
syscall函数
https://man7.org/linux/man-pages/man2/syscalls.2.html
ebpf辅助函数
https://www.man7.org/linux/man-pages/man7/bpf-helpers.7.html
bcc参考文档(可为cilium ebpf提供一致的参考)
https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md
linux内核自测
https://elixir.bootlin.com/linux/latest/source/tools/testing/selftests/bpf


-----------------
开发
### 确定事件类型
kprobe kretprobe 
      内核调试工具 插入到内核中的任何指令，当指定的函数返回时，将触发一个返回探测
uprobe uretprobe 
      用户级别kprobe
Tracepoints
      ls /sys/kernel/debug/tracing/events/syscalls/
      举例 syscalls:sys_enter_open 其中 syscalls 表示子系统模块， sys_enter_open 表示跟踪点名称
      类似kprobe,hook形式实现。速度/稳定性皆优于kprobe，泛用性较小， 优先tracepoint  tracepoint 方式，我们应该优先使用 https://mp.weixin.qq.com/s?__biz=MzA3NjY2NzY1MA==&mid=2649740426&idx=1&sn=2e25fdcc5b01a96b4c9dd3f21eadcec6&chksm=8746bae7b03133f117d2dc50a4554f6a685bcbfc8023ddaf4d6456e3335666a0dda1b1698fbf&scene=27
USDT probes
perf_event
其他：Raw Tracepoints / system call tracepoints / kfuncs / kretfuncs / lsm probes / bpf iterators

### 解析 kprobe   
main.go 主程序
   1. 确定附着函数 sys_execve
   2. 锁定资源内存
   3. loadBpfObjects将预先编译的eBpf程序和map加载在内核 最后调用link.Kprobe机型attch
      编译的eBpf程序和map 和 objs(bofObjects) 都在生成的.go中

kprobe.c 

### 如何自己写一个 ebpf程序
1. 确定附着函数 do_sys_openat2   (strace cat file)
2. 改造.c
我们的目标是获取do_sys_openat2的第二个参数filename.c开始改造：
3. 通过辅助函数获取当前pid_tgid

https://barryx.cn/cilium_ebpf/