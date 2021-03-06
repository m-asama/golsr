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
	"errors"
	"sort"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/m-asama/golsr/internal/pkg/util"
	"github.com/m-asama/golsr/pkg/isis/packet"
)

type Ls struct {
	pdu       *packet.LsPdu
	origin    bool
	srmFlags  map[int]*time.Time
	ssnFlags  map[int]*time.Time
	generated *time.Time
	expired   *time.Time
}

type Lss []*Ls

func (lss Lss) Len() int {
	return len(lss)
}

func (lss Lss) Swap(i, j int) {
	lss[i], lss[j] = lss[j], lss[i]
}

func (lss Lss) Less(i, j int) bool {
	li := lss[i].pdu.LspId()
	lj := lss[j].pdu.LspId()
	return bytes.Compare(li[:], lj[:]) < 0
}

func NewLs(pdu *packet.LsPdu, origin bool, generated *time.Time) (*Ls, error) {
	log.Debugf("enter")
	defer log.Debugf("exit")
	ls := Ls{
		pdu:       pdu,
		origin:    origin,
		generated: generated,
	}
	ls.srmFlags = make(map[int]*time.Time)
	ls.ssnFlags = make(map[int]*time.Time)
	return &ls, nil
}

func (isis *IsisServer) lspLevel(lsp *packet.LsPdu) (IsisLevel, error) {
	log.Debugf("enter")
	defer log.Debugf("exit")
	if lsp == nil {
		return 0, errors.New("lsp invalid")
	}
	switch lsp.PduType() {
	case packet.PDU_TYPE_LEVEL1_LSP:
		return ISIS_LEVEL_1, nil
	case packet.PDU_TYPE_LEVEL2_LSP:
		return ISIS_LEVEL_2, nil
	}
	return 0, errors.New("level invalid")
}

func (isis *IsisServer) insertLsp(lsp *packet.LsPdu, origin bool, generated *time.Time) *Ls {
	log.Debugf("enter: lspid=%x origin=%s generated=%s", lsp.LspId(), origin, generated)
	defer log.Debugf("exit: lspid=%x origin=%s generated=%s", lsp.LspId(), origin, generated)
	level, err := isis.lspLevel(lsp)
	if err != nil {
		return nil
	}
	isis.lock.Lock()
	defer isis.lock.Unlock()
	lsDb := make([]*Ls, 0)
	for _, lstmp := range isis.lsDb[level] {
		ll := lstmp.pdu.LspId()
		lr := lsp.LspId()
		if !bytes.Equal(ll[:], lr[:]) {
			lsDb = append(lsDb, lstmp)
		}
	}
	ls, _ := NewLs(lsp, origin, generated)
	lsDb = append(lsDb, ls)
	isis.lsDb[level] = lsDb
	isis.updateChSend(&UpdateChMsg{
		msgType: UPDATE_CH_MSG_TYPE_LSDB_CHANGED,
	})
	return ls
}

func (isis *IsisServer) deleteLsp(ls *Ls, hasLock bool) {
	log.Debugf("enter: lspid=%x", ls.pdu.LspId())
	defer log.Debugf("exit: lspid=%x", ls.pdu.LspId())
	level, err := isis.lspLevel(ls.pdu)
	if err != nil {
		return
	}
	if !hasLock {
		isis.lock.Lock()
		defer isis.lock.Unlock()
	}
	lsDb := make([]*Ls, 0)
	for _, lstmp := range isis.lsDb[level] {
		if lstmp != ls {
			lsDb = append(lsDb, lstmp)
		}
	}
	isis.lsDb[level] = lsDb
	isis.updateChSend(&UpdateChMsg{
		msgType: UPDATE_CH_MSG_TYPE_LSDB_CHANGED,
	})
}

func (isis *IsisServer) lookupLsp(level IsisLevel, lspId [packet.LSP_ID_LENGTH]byte) *Ls {
	log.Debugf("enter: level=%s lspid=%x", level, lspId)
	defer log.Debugf("exit: level=%s lspid=%x", level, lspId)
	isis.lock.RLock()
	defer isis.lock.RUnlock()
	for _, lstmp := range isis.lsDb[level] {
		ll := lstmp.pdu.LspId()
		if bytes.Equal(ll[:], lspId[:]) {
			return lstmp
		}
	}
	return nil
}

func (isis *IsisServer) originLss(level IsisLevel, nodeId uint8) []*Ls {
	log.Debugf("enter")
	defer log.Debugf("exit")
	isis.lock.RLock()
	defer isis.lock.RUnlock()
	lss := make([]*Ls, 0)
	for _, lstmp := range isis.lsDb[level] {
		ll := lstmp.pdu.LspId()
		if !lstmp.origin ||
			!bytes.Equal(ll[0:packet.SYSTEM_ID_LENGTH], isis.systemId[0:packet.SYSTEM_ID_LENGTH]) ||
			ll[packet.NEIGHBOUR_ID_LENGTH-1] != nodeId {
			continue
		}
		lss = append(lss, lstmp)
	}
	sort.Sort(Lss(lss))
	return lss
}

func (isis *IsisServer) getReachabilities(level IsisLevel, neighId [packet.NEIGHBOUR_ID_LENGTH]byte) *Reachabilities {
	log.Debugf("enter: level=%s neighid=%x", level, neighId)
	defer log.Debugf("exit: level=%s neighid=%x", level, neighId)
	isis.lock.RLock()
	defer isis.lock.RUnlock()
	r := NewReachabilities()
	lss := make([]*Ls, 0)
	for _, lstmp := range isis.lsDb[level] {
		log.Debugf("%s: cand %x", level, lstmp.pdu.LspId())
		ll := lstmp.pdu.LspId()
		if bytes.Equal(ll[0:packet.NEIGHBOUR_ID_LENGTH], neighId[0:packet.NEIGHBOUR_ID_LENGTH]) {
			log.Debugf("%s: found %x", level, lstmp.pdu.LspId())
			lss = append(lss, lstmp)
		}
	}
	sort.Sort(Lss(lss))
	for _, ls := range lss {
		log.Debugf("%s: do %x", level, ls.pdu.LspId())
		widetlvs, _ := ls.pdu.ExtendedIsReachabilityTlvs()
		for _, tlv := range widetlvs {
			for _, n := range tlv.Neighbours() {
				isr := &IsReachability{}
				neighborId := n.NeighbourId()
				copy(isr.neighborId[0:packet.NEIGHBOUR_ID_LENGTH],
					neighborId[0:packet.NEIGHBOUR_ID_LENGTH])
				isr.metric = n.DefaultMetric
				r.addIsReachability(isr)
				log.Debugf("%s: add wide %x", level, isr.neighborId)
			}
		}
		oldtlvs, _ := ls.pdu.IsNeighboursLspTlvs()
		for _, tlv := range oldtlvs {
			for _, n := range tlv.Neighbours() {
				isr := &IsReachability{}
				neighborId := n.NeighbourId()
				copy(isr.neighborId[0:packet.NEIGHBOUR_ID_LENGTH],
					neighborId[0:packet.NEIGHBOUR_ID_LENGTH])
				isr.metric = uint32(n.DefaultMetric)
				r.addIsReachability(isr)
				log.Debugf("%s: add old %x", level, isr.neighborId)
			}
		}
		wideiptlvs, _ := ls.pdu.ExtendedIpReachabilityTlvs()
		for _, tlv := range wideiptlvs {
			for _, n := range tlv.Ipv4Prefixes() {
				log.Debugf("%s: XXX %x", level, n.Ipv4Prefix())
				i4r := &Ipv4Reachability{}
				i4r.ipv4Prefix = n.Ipv4Prefix()
				i4r.prefixLength = n.PrefixLength()
				i4r.metric = n.MetricInformation
				r.addIpv4Reachability(i4r)
				log.Debugf("%s: add ipv4 wide %x/%d", level, i4r.ipv4Prefix, i4r.prefixLength)
			}
		}
		oldiptlvs, _ := ls.pdu.IpInternalReachInfoTlvs()
		for _, tlv := range oldiptlvs {
			for _, n := range tlv.IpSubnets() {
				log.Debugf("%s: XXX %x", level, n.IpAddress)
				i4r := &Ipv4Reachability{}
				i4r.ipv4Prefix = n.IpAddress
				i4r.prefixLength = util.Snmask42plen(n.SubnetMask)
				i4r.metric = uint32(n.DefaultMetric)
				r.addIpv4Reachability(i4r)
				log.Debugf("%s: add ipv4 old %x/%d", level, i4r.ipv4Prefix, i4r.prefixLength)
			}
		}
		ip6tlvs, _ := ls.pdu.Ipv6ReachabilityTlvs()
		for _, tlv := range ip6tlvs {
			for _, n := range tlv.Ipv6Prefixes() {
				i6r := &Ipv6Reachability{}
				i6r.ipv6Prefix = n.Ipv6Prefix()
				i6r.prefixLength = n.PrefixLength()
				i6r.metric = n.Metric
				r.addIpv6Reachability(i6r)
				log.Debugf("%s: add ipv6 %x:%x:%x:%x/%d", level,
					i6r.ipv6Prefix[0], i6r.ipv6Prefix[1], i6r.ipv6Prefix[2], i6r.ipv6Prefix[3],
					i6r.prefixLength)
			}
		}
	}
	return r
}
