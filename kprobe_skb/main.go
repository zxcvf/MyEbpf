package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"reflect"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf skbtracer.c -- -I./headers

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// 定义附着的函数为sys_execve
	// fn := "netif_rx"

	// 锁定当前进程的ebpf资源的内存
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// 将预先编译的ebpf程序和maps加载到内核， 他的定义在生成的.go文件中
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	proto, err := proto2uint8("any")
	if err != nil {
		log.Fatalf(err.Error())
	}

	// fmt.Println((100 << 8), "/")
	bc := BpfConfig{
		// NetNS:     cfg.NetNS,
		// Pid: uint32(1816),
		// IP:        cfg.ip,
		// Port:      (cfg.Port >> 8) & (cfg.Port << 8),
		// IcmpID:    (cfg.IcmpID >> 8) & (cfg.IcmpID << 8),
		// DropStack: bool2uint8(cfg.DropStack),
		// CallStack: bool2uint8(cfg.CallStack),
		Proto: proto,
	}

	// bc.Port = 80

	var h reflect.SliceHeader
	h.Data = uintptr(unsafe.Pointer(&bc))
	h.Len = sizeOfBpfConfig
	h.Cap = sizeOfBpfConfig
	val := *(*[]byte)(unsafe.Pointer(&h))

	cfg := objs.bpfMaps.SkbtracerCfg
	err = cfg.Put(uint32(0), val)
	if err != nil {
		log.Fatal(err.Error())
	}

	funcs := make(map[string]*ebpf.Program)
	funcs["ip_rcv"] = objs.K_ipRcv
	funcs["ip_output"] = objs.K_ipOutput

	// 调用link.Kprobe进行attach
	for fn, sec := range funcs {
		kp, err := link.Kprobe(fn, sec, nil)
		if err != nil {
			log.Fatalf("opening kprobe: %s", err)
		}
		defer kp.Close()
	}

	rd, err := perf.NewReader(objs.SkbtracerEvent, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	go func() {
		// Wait for a signal and close the perf reader,
		// which will interrupt rd.Read() and make the program exit.
		<-stopper
		log.Println("Received signal, exiting program..")

		if err := rd.Close(); err != nil {
			log.Fatalf("closing perf event reader: %s", err)
		}
	}()

	log.Printf("Listening for events..")

	var rcvCount int
	var outputCount int
	var rcvBytes int
	var outputBytes int

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				fmt.Println("count", rcvCount, outputCount)
				fmt.Println("bytes", rcvBytes/5/1024, outputBytes/5/1024)
				rcvCount, outputCount = 0, 0
				rcvBytes, outputBytes = 0, 0
			}
		}
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("reading from perf event reader: %s", err)
			continue
		}

		if record.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		// log.Printf("%s:%s return value: %s", binPath, symbol, unix.ByteSliceToString(event.Line[:]))
		// fmt.Println(record.CPU, string(record.RawSample), reflect.TypeOf(record.RawSample))
		var ev perfEvent

		_ = ev.unmarshal(record.RawSample)

		// fmt.Printf("%-10s %-20s %-12s %-8s %-6s %-18s %-18s %-6s %-54s %s\n",
		// 	"TIME", "SKB", "NETWORK_NS", "PID", "CPU", "INTERFACE", "DEST_MAC", "IP_LEN", "PKT_INFO", "TRACE_INFO"
		fmt.Println(ev.output())
		fmt.Println(ev.iptablesInfo)

		switch ev.getFuncName() {
		case "ip_rcv":
			rcvCount++
			rcvBytes += ev.getSize()
		case "ip_output":
			outputCount++
			outputBytes += ev.getSize()
		}
	}
}
