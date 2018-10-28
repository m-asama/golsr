package main

import (
	"encoding/binary"
	"fmt"
	"github.com/m-asama/golsr/pkg/isis/server"
	"net"
	"os"
	"syscall"
	"unsafe"
)

func handler(fd int) {
	// func Recvfrom(fd int, p []byte, flags int) (n int, from Sockaddr, err error)

	fmt.Println("handler...")
	buf := make([]byte, 8192)
	for {
		fmt.Println("x")
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		fmt.Println("Recvfrom:")
		fmt.Println(n, from, err)
		for i := 0; i < 10; i++ {
			fmt.Printf("%02x ", buf[i])
		}
		fmt.Println("")
	}
}

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func main() {

	if len(os.Args) != 2 {
		os.Exit(1)
	}
	ifname := os.Args[1]

	fmt.Println("=============================================================================")
	fmt.Println("= Start sending                                                             =")
	fmt.Println("=============================================================================")

	/*
		pkt := []byte{
			0x6c, 0x62, 0x6d, 0x50, 0xe6, 0xe4, 0x94, 0xde, 0x80, 0xa5, 0xec, 0x79, 0x08, 0x00, 0x45, 0x00,
			0x00, 0x3c, 0x4b, 0x72, 0x40, 0x00, 0x40, 0x06, 0x44, 0x7d, 0xc0, 0xa8, 0x34, 0x7b, 0xd8, 0x3a,
			0xdd, 0x6e, 0xa6, 0x37, 0x01, 0xbb, 0x32, 0xf3, 0x21, 0xa9, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
			0x72, 0x10, 0xae, 0xa5, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x15, 0x13,
			0x6a, 0xdb, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
		}
	*/
	pkt := []byte{
		0xfe, 0xfe, 0x03, 0x83, 0x1b, 0x01, 0x00, 0x14, 0x01, 0x00, /* ........ */
		0x00, 0x00, 0x63, 0x04, 0x8d, 0x36, 0xd3, 0x64, /* ..c..6.d */
		0x2f, 0x27, 0xad, 0x00, 0x00, 0x00, 0x00, 0x00, /* /'...... */
		0x02, 0xa2, 0xbe, 0x03, 0x81, 0x02, 0xcc, 0x8e, /* ........ */
		0x01, 0x02, 0x01, 0x01, 0x89, 0x08, 0x66, 0x72, /* ......fr */
		0x72, 0x74, 0x65, 0x73, 0x74, 0x31, 0x86, 0x04, /* rtest1.. */
		0xc0, 0xa8, 0x01, 0x01, 0x84, 0x04, 0xc0, 0xa8, /* ........ */
		0x01, 0x01, 0x87, 0x18, 0x00, 0x00, 0x00, 0x0a, /* ........ */
		0x18, 0xc0, 0xa8, 0x0c, 0x00, 0x00, 0x00, 0x0a, /* ........ */
		0x18, 0xc0, 0xa8, 0x0d, 0x00, 0x00, 0x00, 0x0a, /* ........ */
		0x18, 0xc0, 0xa8, 0x01, 0xec, 0x0e, 0x00, 0x00, /* ........ */
		0x00, 0x0a, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, /* ...@ ... */
		0x00, 0x00, 0x00, 0x01,
	}

	//fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, syscall.ETH_P_ALL)
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(uint16(syscall.ETH_P_ALL))))
	if err != nil {
		fmt.Println("=============================================================================")
		fmt.Println("= Error 1                                                                   =")
		fmt.Println("=============================================================================")
		fmt.Println(err)
	}

	filter := make([]server.SockFilter, 6)
	filter[0] = server.SockFilter{0x28, 0, 0, 0x0000000e - 14}
	filter[1] = server.SockFilter{0x15, 0, 3, 0x0000fefe}
	filter[2] = server.SockFilter{0x30, 0, 0, 0x00000011 - 14}
	filter[3] = server.SockFilter{0x15, 0, 1, 0x00000083}
	filter[4] = server.SockFilter{0x6, 0, 0, 0x00040000}
	filter[5] = server.SockFilter{0x6, 0, 0, 0x00000000}
	bpf := server.SockFprog{
		Len:    6,
		Filter: (*server.SockFilter)(unsafe.Pointer(&filter[0])),
	}
	server.SetsockoptAttachFilter(fd, syscall.SOL_SOCKET, syscall.SO_ATTACH_FILTER, &bpf)
	if err != nil {
		fmt.Println("=============================================================================")
		fmt.Println("= Error x                                                                   =")
		fmt.Println("=============================================================================")
		fmt.Println(err)
	}

	if_info, err := net.InterfaceByName(ifname)
	if err != nil {
		fmt.Println("=============================================================================")
		fmt.Println("= Error 2                                                                   =")
		fmt.Println("=============================================================================")
		fmt.Println(err)
	}

	addr := syscall.SockaddrLinklayer{
		Protocol: syscall.ETH_P_ALL,
		Ifindex:  if_info.Index,
	}
	addr.Protocol = htons(uint16(syscall.ETH_P_ALL))
	err = syscall.Bind(fd, &addr)

	/*
		copy(pkt[6:12], if_info.HardwareAddr[0:6])
		fmt.Println(len(if_info.HardwareAddr))

		var haddr [8]byte
		copy(haddr[0:7], if_info.HardwareAddr[0:7])
		addr := syscall.SockaddrLinklayer{
			Protocol: syscall.ETH_P_IP,
			Ifindex:  if_info.Index,
			Halen:    uint8(len(if_info.HardwareAddr)),
			Addr:     haddr,
		}
	*/

	AllL1ISS := []byte{0x01, 0x80, 0xC2, 0x00, 0x00, 0x14}
	//	AllL2ISS := []byte{0x01, 0x80, 0xC2, 0x00, 0x00, 0x15}
	//	AllISS := []byte{0x09, 0x00, 0x2B, 0x00, 0x00, 0x05}

	mreq := server.PacketMreq{
		Ifindex: int32(if_info.Index),
		Type:    syscall.PACKET_MR_MULTICAST,
		ALen:    uint16(len(if_info.HardwareAddr)),
	}
	copy(mreq.Address[0:6], AllL1ISS[0:6])
	mreq.Address[6] = 0x0
	mreq.Address[7] = 0x0
	/*
		mreq := server.PacketMreq{
			Ifindex: int32(if_info.Index),
			Type:    syscall.PACKET_MR_PROMISC,
		}
	*/

	err = server.SetsockoptPacketMreq(fd, syscall.SOL_PACKET, syscall.PACKET_ADD_MEMBERSHIP, &mreq)
	if err != nil {
		fmt.Println("=============================================================================")
		fmt.Println("= Error x                                                                   =")
		fmt.Println("=============================================================================")
		fmt.Println(err)
	}

	var dad [8]byte
	copy(dad[0:6], []byte{0x01, 0x80, 0xC2, 0x00, 0x00, 0x14}[0:6])
	dad[6] = 0x0
	dad[7] = 0x0
	dstaddr := syscall.SockaddrLinklayer{
		Protocol: syscall.ETH_P_IP,
		Ifindex:  if_info.Index,
		Halen:    uint8(len(if_info.HardwareAddr)),
		Addr:     dad,
	}
	err = syscall.Sendto(fd, pkt, 0, &dstaddr)
	if err != nil {
		fmt.Println("=============================================================================")
		fmt.Println("= Error 5                                                                   =")
		fmt.Println("=============================================================================")
		fmt.Println(err)
	} else {
		fmt.Println("=============================================================================")
		fmt.Println("= Packet is sent                                                            =")
		fmt.Println("=============================================================================")
	}
	handler(fd)

}
