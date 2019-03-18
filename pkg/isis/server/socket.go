//
// Copyright (C) 2019-2019 Masakazu Asama.
// Copyright (C) 2019-2019 Ginzado Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"encoding/binary"
	"errors"
	"syscall"
	"unsafe"

	log "github.com/sirupsen/logrus"

	"github.com/m-asama/golsr/internal/pkg/kernel"
	"github.com/m-asama/golsr/pkg/isis/packet"
)

func htons(s uint16) uint16 {
	b := []byte{byte(s & 0xff), byte(s >> 8)}
	return binary.BigEndian.Uint16(b)
}

func isisSocket(iface *kernel.Interface) (int, error) {
	var err error

	if iface == nil {
		s := "iface == nil"
		log.Infof(s)
		return -1, errors.New(s)
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(uint16(syscall.ETH_P_ALL))))
	if err != nil {
		s := "syscall.Socket failed"
		log.Infof(s)
		return -1, errors.New(s)
	}

	filter := make([]SockFilter, 6)
	filter[0] = SockFilter{0x28, 0, 0, 0x0000000e - 14}
	filter[1] = SockFilter{0x15, 0, 3, 0x0000fefe}
	filter[2] = SockFilter{0x30, 0, 0, 0x00000011 - 14}
	filter[3] = SockFilter{0x15, 0, 1, 0x00000083}
	filter[4] = SockFilter{0x6, 0, 0, 0x00040000}
	filter[5] = SockFilter{0x6, 0, 0, 0x00000000}
	bpf := SockFprog{
		Len:    6,
		Filter: (*SockFilter)(unsafe.Pointer(&filter[0])),
	}
	SetsockoptAttachFilter(fd, syscall.SOL_SOCKET, syscall.SO_ATTACH_FILTER, &bpf)
	if err != nil {
		s := "SetsockoptAttachFilter failed"
		log.Infof(s)
		return -1, errors.New(s)
	}

	addr := syscall.SockaddrLinklayer{
		Protocol: syscall.ETH_P_ALL,
		Ifindex:  iface.IfIndex,
	}
	addr.Protocol = htons(uint16(syscall.ETH_P_ALL))
	err = syscall.Bind(fd, &addr)
	if err != nil {
		s := "syscall.Bind failed"
		log.Infof(s)
		return -1, errors.New(s)
	}

	mreqAddrs := [][]byte{packet.AllL1Iss, packet.AllL2Iss, packet.AllIss}
	for _, mreqAddr := range mreqAddrs {
		mreq := PacketMreq{
			Ifindex: int32(iface.IfIndex),
			Type:    syscall.PACKET_MR_MULTICAST,
			ALen:    uint16(len(mreqAddr)),
		}
		copy(mreq.Address[0:6], mreqAddr[0:6])
		mreq.Address[6] = 0x0
		mreq.Address[7] = 0x0

		err = SetsockoptPacketMreq(fd, syscall.SOL_PACKET, syscall.PACKET_ADD_MEMBERSHIP, &mreq)
		if err != nil {
			s := "SetsockoptPacketMreq failed"
			log.Infof(s)
			return -1, errors.New(s)
		}
	}

	return fd, nil
}
