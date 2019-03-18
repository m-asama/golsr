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
