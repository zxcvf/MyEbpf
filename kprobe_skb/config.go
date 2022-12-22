package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"unsafe"
)

const sizeOfBpfConfig = int(unsafe.Sizeof(BpfConfig{}))

type BpfConfig struct {
	NetNS     uint32
	Pid       uint32
	IP        uint32
	Port      uint16
	IcmpID    uint16
	DropStack uint8
	CallStack uint8
	Proto     uint8
	pad       uint8
}

func bool2uint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func ip2uint32(s string) (uint32, error) {
	if s == "" {
		return 0, errors.New("ip 不能为空")
	}
	ip := net.ParseIP(s)
	ip = ip.To4()

	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4 addr (%s)", ip)
	}

	return binary.BigEndian.Uint32(ip), nil
}

func proto2uint8(s string) (uint8, error) {
	switch s {
	case "tcp":
		return 6, nil
	case "udp":
		return 17, nil
	case "icmp":
		return 1, nil
	case "any", "":
		return 0, nil
	default:
		return 0, fmt.Errorf("invalid proto (%s)", s)
	}
}
