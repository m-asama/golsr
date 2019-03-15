package util

import (
	"net"
)

func Plen2snmask4(plen uint8) uint32 {
	return uint32(((uint64(1) << plen) - 1) << (32 - plen))
}

func Snmask42plen(snmask uint32) uint8 {
	var i uint8
	for i = 0; i <= 32; i++ {
		if snmask == Plen2snmask4(i) {
			return i
		}
	}
	return 32
}

func Ipv4Uint32ToString(addr uint32) string {
	ip := make([]byte, 4)
	for i := 0; i < 4; i++ {
		ip[i] = byte(addr >> uint(((3 - i%4) * 8)))
	}
	return (net.IP(ip)).String()
}

func Ipv6Uint32ArrayToString(addr [4]uint32) string {
	ip := make([]byte, 16)
	for i := 0; i < 16; i++ {
		ip[i] = byte(addr[i/4] >> uint(((3 - i%4) * 8)))
	}
	return (net.IP(ip)).String()
}
