package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go  -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf tracepoint.c -- -I../headers

const mapKey uint32 = 0

// *****   go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf kprobe.c -- -I../headers

func main() {
	// 定义附着的函数为sys_execve
	fn := "sys_enter_execve"

	// 锁定当前进程的ebpf资源的内存
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	// 将预先编译的ebpf程序和maps加载到内核， 他的定义在生成的.go文件中
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects>>>>>>>>  %v", err)
	}
	defer objs.Close()

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.
	// 调用link.Kprobe进行attach
	// kp, err := link.Kprobe(fn, objs.KprobeExecve, nil)
	tp, err := link.Tracepoint("syscalls", fn, objs.EnterExecve, nil)

	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer tp.Close()

	// rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	rd, err := perf.NewReader(objs.bpfMaps.EventMap, os.Getpagesize())
	if err != nil {
		log.Fatalf("reader err: %s", err.Error())
	}
	for {

		ev, err := rd.Read()
		if err != nil {
			log.Fatalf("Read fail")
		}

		if ev.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", ev.LostSamples)
			continue
		}
		b_arr := bytes.NewBuffer(ev.RawSample)

		var data exec_data_t
		if err := binary.Read(b_arr, binary.LittleEndian, &data); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}

		// fmt.Printf("On cpu %02d %s ran : %d %s\n", ev.CPU, data.Comm, data.Pid, data.F_name)
		fmt.Printf("On cpu %02d  pid: %d filename: %s comm: %s \n", ev.CPU, data.Pid, data.F_name, data.Comm)
	}

}

type exec_data_t struct {
	Pid    uint32
	F_name [32]byte
	Comm   [32]byte
}

//  objs 由.c文件定义
