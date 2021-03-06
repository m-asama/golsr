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
	"bytes"
	"sort"

	log "github.com/sirupsen/logrus"

	"github.com/m-asama/golsr/pkg/isis/packet"
)

type IsReachability struct {
	neighborId [packet.NEIGHBOUR_ID_LENGTH]byte
	metric     uint32
	lspNumber  int
	wideMetric bool
	ls         *Ls
}

type IsReachabilities []*IsReachability

func (rs IsReachabilities) Len() int {
	return len(rs)
}

func (rs IsReachabilities) Swap(i, j int) {
	rs[i], rs[j] = rs[j], rs[i]
}

func (rs IsReachabilities) Less(i, j int) bool {
	return bytes.Compare(rs[i].neighborId[:], rs[j].neighborId[:]) < 0
}

func (isis *IsisServer) newIsReachabilities(level IsisLevel) []*IsReachability {
	log.Debugf("enter")
	defer log.Debugf("exit")
	new := make([]*IsReachability, 0)
	for _, circuit := range isis.circuitDb {
		if !circuit.enable() || !circuit.kernelUp() {
			continue
		}
		if circuit.configBcast() {
			neighborId := circuit.lanId(level)
			isr := &IsReachability{
				neighborId: neighborId,
				metric:     circuit.metric(level),
				lspNumber:  -1,
				wideMetric: isis.wide(level),
			}
			new = append(new, isr)
		} else {
			for _, adjacency := range circuit.adjacencyDb {
				if adjacency.adjState != packet.ADJ_3WAY_STATE_UP {
					continue
				}
				var neighborId [packet.NEIGHBOUR_ID_LENGTH]byte
				copy(neighborId[0:packet.SYSTEM_ID_LENGTH],
					adjacency.systemId[0:packet.SYSTEM_ID_LENGTH])
				isr := &IsReachability{
					neighborId: neighborId,
					metric:     circuit.metric(level),
					lspNumber:  -1,
					wideMetric: isis.wide(level),
				}
				new = append(new, isr)
			}
		}
	}
	for _, ctmp := range isis.isReachabilities[level] {
		for _, ntmp := range new {
			if bytes.Equal(ntmp.neighborId[:], ctmp.neighborId[:]) {
				ntmp.lspNumber = ctmp.lspNumber
			}
		}
	}
	sort.Sort(IsReachabilities(new))
	return new
}

func (isis *IsisServer) isReachabilitiesChanged(level IsisLevel, new []*IsReachability) bool {
	log.Debugf("enter")
	defer log.Debugf("exit")
	current := isis.isReachabilities[level]
	if len(current) != len(new) {
		return true
	}
	for i := 0; i < len(current); i++ {
		if !bytes.Equal(current[i].neighborId[:], new[i].neighborId[:]) ||
			current[i].metric != new[i].metric {
			return true
		}
	}
	return false
}

type Ipv4Reachability struct {
	ipv4Prefix   uint32
	prefixLength uint8
	scopeHost    bool
	metric       uint32
	lspNumber    int
	wideMetric   bool
	down         bool
	ls           *Ls
}

type Ipv4Reachabilities []*Ipv4Reachability

func (rs Ipv4Reachabilities) Len() int {
	return len(rs)
}

func (rs Ipv4Reachabilities) Swap(i, j int) {
	rs[i], rs[j] = rs[j], rs[i]
}

func (rs Ipv4Reachabilities) Less(i, j int) bool {
	if rs[i].ipv4Prefix != rs[j].ipv4Prefix {
		return rs[i].ipv4Prefix < rs[j].ipv4Prefix
	}
	return rs[i].prefixLength < rs[j].prefixLength
}

func (isis *IsisServer) newIpv4Reachabilities(level IsisLevel) []*Ipv4Reachability {
	log.Debugf("enter")
	defer log.Debugf("exit")
	new := make([]*Ipv4Reachability, 0)
	if !isis.ipv4Enable() {
		return new
	}
	for _, iface := range isis.kernel.Interfaces {
		circuit, ok := isis.circuitDb[iface.IfIndex]
		if !ok {
			continue
		}
		if !circuit.enable() || !circuit.kernelUp() {
			continue
		}
		for _, ipv4Address := range iface.Ipv4Addresses {
			ipv4r := &Ipv4Reachability{
				ipv4Prefix:   ipv4Address.Address,
				prefixLength: uint8(ipv4Address.PrefixLength),
				scopeHost:    ipv4Address.ScopeHost,
				metric:       circuit.metric(level),
				lspNumber:    -1,
				wideMetric:   isis.wide(level),
				down:         false,
			}
			new = append(new, ipv4r)
		}
	}
	for _, ctmp := range isis.ipv4Reachabilities[level] {
		for _, ntmp := range new {
			if ntmp.ipv4Prefix == ctmp.ipv4Prefix &&
				ntmp.prefixLength == ctmp.prefixLength {
				ntmp.lspNumber = ctmp.lspNumber
			}
		}
	}
	sort.Sort(Ipv4Reachabilities(new))
	return new
}

func (isis *IsisServer) ipv4ReachabilitiesChanged(level IsisLevel, new []*Ipv4Reachability) bool {
	log.Debugf("enter")
	defer log.Debugf("exit")
	current := isis.ipv4Reachabilities[level]
	if len(current) != len(new) {
		return true
	}
	for i := 0; i < len(current); i++ {
		if current[i].ipv4Prefix != new[i].ipv4Prefix ||
			current[i].prefixLength != new[i].prefixLength ||
			current[i].metric != new[i].metric {
			return true
		}
	}
	return false
}

type Ipv6Reachability struct {
	ipv6Prefix   [4]uint32
	prefixLength uint8
	scopeLink    bool
	scopeHost    bool
	metric       uint32
	lspNumber    int
	down         bool
	external     bool
	ls           *Ls
}

type Ipv6Reachabilities []*Ipv6Reachability

func (rs Ipv6Reachabilities) Len() int {
	return len(rs)
}

func (rs Ipv6Reachabilities) Swap(i, j int) {
	rs[i], rs[j] = rs[j], rs[i]
}

func (rs Ipv6Reachabilities) Less(i, j int) bool {
	if rs[i].ipv6Prefix[0] != rs[j].ipv6Prefix[0] {
		return rs[i].ipv6Prefix[0] < rs[j].ipv6Prefix[0]
	}
	if rs[i].ipv6Prefix[1] != rs[j].ipv6Prefix[1] {
		return rs[i].ipv6Prefix[1] < rs[j].ipv6Prefix[1]
	}
	if rs[i].ipv6Prefix[2] != rs[j].ipv6Prefix[2] {
		return rs[i].ipv6Prefix[2] < rs[j].ipv6Prefix[2]
	}
	if rs[i].ipv6Prefix[3] != rs[j].ipv6Prefix[3] {
		return rs[i].ipv6Prefix[3] < rs[j].ipv6Prefix[3]
	}
	return rs[i].prefixLength < rs[j].prefixLength
}

func (isis *IsisServer) newIpv6Reachabilities(level IsisLevel) []*Ipv6Reachability {
	log.Debugf("enter")
	defer log.Debugf("exit")
	new := make([]*Ipv6Reachability, 0)
	if !isis.ipv6Enable() {
		return new
	}
	for _, iface := range isis.kernel.Interfaces {
		circuit, ok := isis.circuitDb[iface.IfIndex]
		if !ok {
			continue
		}
		if !circuit.enable() || !circuit.kernelUp() {
			continue
		}
		for _, ipv6Address := range iface.Ipv6Addresses {
			ipv6r := &Ipv6Reachability{
				ipv6Prefix: [4]uint32{
					ipv6Address.Address[0],
					ipv6Address.Address[1],
					ipv6Address.Address[2],
					ipv6Address.Address[3],
				},
				prefixLength: uint8(ipv6Address.PrefixLength),
				scopeLink:    ipv6Address.ScopeLink,
				scopeHost:    ipv6Address.ScopeHost,
				metric:       circuit.metric(level),
				lspNumber:    -1,
				down:         false,
				external:     false,
			}
			new = append(new, ipv6r)
		}
	}
	for _, ctmp := range isis.ipv6Reachabilities[level] {
		for _, ntmp := range new {
			if ntmp.ipv6Prefix[0] == ctmp.ipv6Prefix[0] &&
				ntmp.ipv6Prefix[1] == ctmp.ipv6Prefix[1] &&
				ntmp.ipv6Prefix[2] == ctmp.ipv6Prefix[2] &&
				ntmp.ipv6Prefix[3] == ctmp.ipv6Prefix[3] &&
				ntmp.prefixLength == ctmp.prefixLength {
				ntmp.lspNumber = ctmp.lspNumber
			}
		}
	}
	sort.Sort(Ipv6Reachabilities(new))
	return new
}

func (isis *IsisServer) ipv6ReachabilitiesChanged(level IsisLevel, new []*Ipv6Reachability) bool {
	log.Debugf("enter")
	defer log.Debugf("exit")
	current := isis.ipv6Reachabilities[level]
	if len(current) != len(new) {
		return true
	}
	for i := 0; i < len(current); i++ {
		if current[i].ipv6Prefix[0] != new[i].ipv6Prefix[0] ||
			current[i].ipv6Prefix[1] != new[i].ipv6Prefix[1] ||
			current[i].ipv6Prefix[2] != new[i].ipv6Prefix[2] ||
			current[i].ipv6Prefix[3] != new[i].ipv6Prefix[3] ||
			current[i].prefixLength != new[i].prefixLength ||
			current[i].metric != new[i].metric {
			return true
		}
	}
	return false
}

type Reachabilities struct {
	isReachabilities   []*IsReachability
	ipv4Reachabilities []*Ipv4Reachability
	ipv6Reachabilities []*Ipv6Reachability
}

func NewReachabilities() *Reachabilities {
	reachabilities := &Reachabilities{
		isReachabilities:   make([]*IsReachability, 0),
		ipv4Reachabilities: make([]*Ipv4Reachability, 0),
		ipv6Reachabilities: make([]*Ipv6Reachability, 0),
	}
	return reachabilities
}

func (rs *Reachabilities) addIsReachability(ir *IsReachability) {
	newIrs := make([]*IsReachability, 0)
	for _, irTmp := range rs.isReachabilities {
		if bytes.Compare(irTmp.neighborId[:], ir.neighborId[:]) != 0 &&
			irTmp.metric != ir.metric {
			newIrs = append(newIrs, irTmp)
		}
	}
	newIrs = append(newIrs, ir)
	rs.isReachabilities = newIrs
}

func (rs *Reachabilities) addIpv4Reachability(ir *Ipv4Reachability) {
	newIrs := make([]*Ipv4Reachability, 0)
	for _, irTmp := range rs.ipv4Reachabilities {
		if irTmp.ipv4Prefix != ir.ipv4Prefix &&
			irTmp.prefixLength != ir.prefixLength {
			newIrs = append(newIrs, irTmp)
		}
	}
	newIrs = append(newIrs, ir)
	rs.ipv4Reachabilities = newIrs
}

func (rs *Reachabilities) addIpv6Reachability(ir *Ipv6Reachability) {
	newIrs := make([]*Ipv6Reachability, 0)
	for _, irTmp := range rs.ipv6Reachabilities {
		if irTmp.ipv6Prefix[0] != ir.ipv6Prefix[0] &&
			irTmp.ipv6Prefix[1] != ir.ipv6Prefix[1] &&
			irTmp.ipv6Prefix[2] != ir.ipv6Prefix[2] &&
			irTmp.ipv6Prefix[3] != ir.ipv6Prefix[3] &&
			irTmp.prefixLength != ir.prefixLength {
			newIrs = append(newIrs, irTmp)
		}
	}
	newIrs = append(newIrs, ir)
	rs.ipv6Reachabilities = newIrs
}
