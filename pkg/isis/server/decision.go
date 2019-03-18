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
	"encoding/binary"
	"fmt"
	"sort"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/m-asama/golsr/pkg/isis/packet"
)

type DecisionChMsgType uint8

const (
	_ DecisionChMsgType = iota
	DECISION_CH_MSG_TYPE_DO
	DECISION_CH_MSG_TYPE_EXIT
)

func (msgType DecisionChMsgType) String() string {
	switch msgType {
	case DECISION_CH_MSG_TYPE_DO:
		return "DECISION_CH_MSG_TYPE_DO"
	case DECISION_CH_MSG_TYPE_EXIT:
		return "DECISION_CH_MSG_TYPE_EXIT"
	}
	log.Infof("")
	panic("")
	return fmt.Sprintf("DecisionChMsgType(%d)", msgType)
}

type DecisionChMsg struct {
	msgType DecisionChMsgType
}

func (msg *DecisionChMsg) String() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s", msg.msgType.String())
	return b.String()
}

type spfIdType uint8

const (
	_ spfIdType = iota
	SPF_ID_TYPE_NODE
	SPF_ID_TYPE_IPV4
	SPF_ID_TYPE_IPV6
)

func (spfIdType spfIdType) String() string {
	switch spfIdType {
	case SPF_ID_TYPE_NODE:
		return "SPF_ID_TYPE_NODE"
	case SPF_ID_TYPE_IPV4:
		return "SPF_ID_TYPE_IPV4"
	case SPF_ID_TYPE_IPV6:
		return "SPF_ID_TYPE_IPV6"
	}
	log.Infof("")
	panic("")
	return fmt.Sprintf("spfIdType(%d)", spfIdType)
}

type spfId struct {
	idType            spfIdType
	nodeId            [packet.NEIGHBOUR_ID_LENGTH]byte
	ipv4PrefixAddress uint32
	ipv4PrefixLength  uint8
	ipv6PrefixAddress [4]uint32
	ipv6PrefixLength  uint8
}

func NewSpfIdNode(nodeId [packet.NEIGHBOUR_ID_LENGTH]byte) *spfId {
	id := &spfId{
		idType: SPF_ID_TYPE_NODE,
		nodeId: nodeId,
	}
	return id
}

func NewSpfIdIpv4(prefixAddress uint32, prefixLength uint8) *spfId {
	id := &spfId{
		idType:            SPF_ID_TYPE_IPV4,
		ipv4PrefixAddress: prefixAddress,
		ipv4PrefixLength:  prefixLength,
	}
	return id
}

func NewSpfIdIpv6(prefixAddress [4]uint32, prefixLength uint8) *spfId {
	id := &spfId{
		idType:            SPF_ID_TYPE_IPV6,
		ipv6PrefixAddress: prefixAddress,
		ipv6PrefixLength:  prefixLength,
	}
	return id
}

func (spfId *spfId) String() string {
	switch spfId.idType {
	case SPF_ID_TYPE_NODE:
		return fmt.Sprintf("NODE %x", spfId.nodeId)
	case SPF_ID_TYPE_IPV4:
		return fmt.Sprintf("IPV4 %08x/%d", spfId.ipv4PrefixAddress, spfId.ipv4PrefixLength)
	case SPF_ID_TYPE_IPV6:
		return fmt.Sprintf("IPV6 %08x:%08x:%08x:%08x/%d",
			spfId.ipv6PrefixAddress[0],
			spfId.ipv6PrefixAddress[1],
			spfId.ipv6PrefixAddress[2],
			spfId.ipv6PrefixAddress[3],
			spfId.ipv6PrefixLength)
	}
	log.Infof("")
	panic("")
	return ""
}

const SPF_ID_KEY_LENGTH = 18

func (spfId *spfId) key() [SPF_ID_KEY_LENGTH]byte {
	var key [SPF_ID_KEY_LENGTH]byte
	switch spfId.idType {
	case SPF_ID_TYPE_NODE:
		key[0] = uint8(SPF_ID_TYPE_NODE)
		copy(key[2:2+packet.NEIGHBOUR_ID_LENGTH], spfId.nodeId[0:packet.NEIGHBOUR_ID_LENGTH])
		return key
	case SPF_ID_TYPE_IPV4:
		key[0] = uint8(SPF_ID_TYPE_IPV4)
		key[1] = spfId.ipv4PrefixLength
		binary.BigEndian.PutUint32(key[2:6], spfId.ipv4PrefixAddress)
		return key
	case SPF_ID_TYPE_IPV6:
		key[0] = uint8(SPF_ID_TYPE_IPV6)
		key[1] = spfId.ipv6PrefixLength
		binary.BigEndian.PutUint32(key[2:6], spfId.ipv6PrefixAddress[0])
		binary.BigEndian.PutUint32(key[6:10], spfId.ipv6PrefixAddress[1])
		binary.BigEndian.PutUint32(key[10:14], spfId.ipv6PrefixAddress[2])
		binary.BigEndian.PutUint32(key[14:18], spfId.ipv6PrefixAddress[3])
		return key
	}
	log.Infof("")
	panic("")
	return key
}

func (l *spfId) Less(r *spfId) bool {
	lb := l.key()
	rb := r.key()
	for i := 0; i < SPF_ID_KEY_LENGTH; i++ {
		if lb[i] == rb[i] {
			continue
		}
		if lb[i] < rb[i] {
			return true
		}
	}
	return false
}

type spfDistance struct {
	internal uint32
	external uint32
}

func NewSpfDistance(internal, external uint32) *spfDistance {
	distance := &spfDistance{
		internal: internal,
		external: external,
	}
	return distance
}

func (l *spfDistance) Less(r *spfDistance) bool {
	if l.external == r.external {
		return l.internal < r.internal
	}
	return l.external < r.external
}

func (l *spfDistance) Equal(r *spfDistance) bool {
	if l.external == r.external &&
		l.internal == r.internal {
		return true
	}
	return false
}

func (l *spfDistance) Add(r *spfDistance) *spfDistance {
	l.internal += r.internal
	for l.internal > MAX_PATH_METRIC {
		l.internal -= MAX_PATH_METRIC
		l.external += 1
	}
	l.external += r.external
	return l
}

type spfTriple struct {
	id          *spfId
	distance    *spfDistance
	adjacencies []*Adjacency
}

func NewSpfTriple(id *spfId, distance *spfDistance) *spfTriple {
	triple := &spfTriple{
		id:          id,
		distance:    distance,
		adjacencies: make([]*Adjacency, 0),
	}
	return triple
}

func (triple *spfTriple) addAdjacency(adjacency *Adjacency) {
	for _, adjtmp := range triple.adjacencies {
		if adjtmp == adjacency {
			return
		}
	}
	triple.adjacencies = append(triple.adjacencies, adjacency)
}

type spfTriples struct {
	triples []*spfTriple
}

func NewSpfTriples() *spfTriples {
	triples := &spfTriples{
		triples: make([]*spfTriple, 0),
	}
	return triples
}

func (triples *spfTriples) Len() int {
	return len(triples.triples)
}

func (triples *spfTriples) Swap(i, j int) {
	triples.triples[i], triples.triples[j] = triples.triples[j], triples.triples[i]
}

func (triples *spfTriples) Less(i, j int) bool {
	if !triples.triples[i].distance.Equal(triples.triples[j].distance) {
		return triples.triples[i].distance.Less(triples.triples[j].distance)
	}
	if triples.triples[i].id.idType != triples.triples[j].id.idType {
		return triples.triples[i].id.idType < triples.triples[j].id.idType
	}
	if triples.triples[i].id.idType != SPF_ID_TYPE_NODE {
		return triples.triples[i].id.Less(triples.triples[j].id)
	}
	pnidi := packet.NEIGHBOUR_ID_LENGTH - 1
	if triples.triples[i].id.nodeId[pnidi] != triples.triples[j].id.nodeId[pnidi] {
		return triples.triples[i].id.nodeId[pnidi] > triples.triples[j].id.nodeId[pnidi]
	}
	return triples.triples[i].id.Less(triples.triples[j].id)
}

func (triples *spfTriples) findTriple(id *spfId) *spfTriple {
	log.Debugf("*** %s", id)
	for _, triple := range triples.triples {
		if triple.id.key() == id.key() {
			return triple
		}
	}
	return nil
}

func (triples *spfTriples) findOrNewTriple(id *spfId) *spfTriple {
	log.Debugf("*** %s", id)
	triple := triples.findTriple(id)
	if triple != nil {
		return triple
	}
	return NewSpfTriple(id, NewSpfDistance(MAX_PATH_METRIC, MAX_PATH_METRIC))
}

func (triples *spfTriples) addTriple(triple *spfTriple) {
	log.Debugf("*** %s", triple.id)
	tstmp := make([]*spfTriple, 0)
	for _, ttmp := range triples.triples {
		if ttmp.id.key() == triple.id.key() {
			continue
		}
		tstmp = append(tstmp, ttmp)
	}
	tstmp = append(tstmp, triple)
	triples.triples = tstmp
	sort.Sort(triples)
}

func (triples *spfTriples) removeTriple(triple *spfTriple) {
	tstmp := make([]*spfTriple, 0)
	for _, ttmp := range triples.triples {
		if ttmp.id.key() == triple.id.key() {
			continue
		}
		tstmp = append(tstmp, ttmp)
	}
	triples.triples = tstmp
}

type Ipv4Nh struct {
	nexthopAddress   uint32
	nexthopInterface *Circuit
}

type Ipv4Ri struct {
	prefixAddress uint32
	prefixLength  uint8
	nexthops      []*Ipv4Nh
	metric        uint32
}

type Ipv6Nh struct {
	nexthopAddress   [4]uint32
	nexthopInterface *Circuit
}

type Ipv6Ri struct {
	prefixAddress [4]uint32
	prefixLength  uint8
	nexthops      []*Ipv6Nh
	metric        uint32
}

func (isis *IsisServer) spf(level IsisLevel, cancelSpfCh, doneSpfCh chan struct{}) {
	log.Debugf("enter: %s", level)
	defer log.Debugf("exit: %s", level)

	// rfc1195 p.55 Step0
	paths := NewSpfTriples()
	tent := NewSpfTriples()
	tentlength := NewSpfDistance(0, 0)
	var tmp *spfTriple
	var r *Reachabilities
	step := 0

	isis.debugPrint(level, paths, tent, &step, "before Step0 1)")

	// rfc1195 p.55 Step0 1)
	selfId := [packet.NEIGHBOUR_ID_LENGTH]byte{}
	copy(selfId[0:packet.SYSTEM_ID_LENGTH], isis.systemId[0:packet.SYSTEM_ID_LENGTH])
	self := NewSpfTriple(NewSpfIdNode(selfId), NewSpfDistance(0, 0))
	paths.addTriple(self)

	isis.debugPrint(level, paths, tent, &step, "before Step0 2)")

	// rfc1195 p.55 Step0 2)
	for _, circuit := range isis.circuitDb {
		for _, adjacency := range circuit.adjacencyDb {
			if adjacency.adjState != packet.ADJ_3WAY_STATE_UP {
				continue
			}
			if !adjacency.level(level) {
				continue
			}
			d := NewSpfDistance(circuit.metric(level), 0)
			nodeId := [packet.NEIGHBOUR_ID_LENGTH]byte{}
			copy(nodeId[0:packet.SYSTEM_ID_LENGTH], adjacency.systemId[0:packet.SYSTEM_ID_LENGTH])
			triple := tent.findOrNewTriple(NewSpfIdNode(nodeId))
			if triple.distance.Equal(d) {
				triple.addAdjacency(adjacency)
				tent.addTriple(triple)
			} else if !triple.distance.Less(d) {
				triple.distance = d
				triple.adjacencies = []*Adjacency{adjacency}
				tent.addTriple(triple)
			}
		}
	}
	// rfc1195 p.55 Step0 8) 9)
	// XXX:
	goto STEP2

STEP1:
	isis.debugPrint(level, paths, tent, &step, "STEP1")
	// rfc1195 p.56 Step1
	if tmp == nil || tmp.id.idType != SPF_ID_TYPE_NODE {
		panic("")
	}
	log.Debugf("%s: tmp.id.nodeId = %x", level, tmp.id.nodeId)
	r = isis.getReachabilities(level, tmp.id.nodeId)
	if r == nil {
		log.Debugf("Reachabilities nil: %s", level)
		goto STEP2
	}
	for _, isr := range r.isReachabilities {
		log.Debugf("XXXXXXXX %s: %x", level, isr.neighborId)
		d := NewSpfDistance(tmp.distance.internal, tmp.distance.external)
		d.Add(NewSpfDistance(isr.metric, 0))
		if d.external > 0 {
			log.Debugf("d.external > 0: %s", level)
			continue
		}
		nodeId := [packet.NEIGHBOUR_ID_LENGTH]byte{}
		copy(nodeId[0:packet.NEIGHBOUR_ID_LENGTH], isr.neighborId[0:packet.NEIGHBOUR_ID_LENGTH])
		if paths.findTriple(NewSpfIdNode(nodeId)) != nil {
			log.Debugf("paths.findTriple(NewSpfIdNode(nodeId)) != nil: %s", level)
			continue
		}
		triple := tent.findOrNewTriple(NewSpfIdNode(nodeId))
		if triple.distance.Equal(d) {
			for _, adj := range tmp.adjacencies {
				triple.addAdjacency(adj)
			}
			tent.addTriple(triple)
		} else if !triple.distance.Less(d) {
			triple.distance = d
			triple.adjacencies = []*Adjacency{}
			for _, adj := range tmp.adjacencies {
				triple.addAdjacency(adj)
			}
			tent.addTriple(triple)
		}
	}
	for _, isr := range r.ipv4Reachabilities {
		d := NewSpfDistance(tmp.distance.internal, tmp.distance.external)
		d.Add(NewSpfDistance(isr.metric, 0))
		if d.external > 0 {
			continue
		}
		node := NewSpfIdIpv4(isr.ipv4Prefix, isr.prefixLength)
		if paths.findTriple(node) != nil {
			continue
		}
		triple := tent.findOrNewTriple(node)
		if triple.distance.Equal(d) {
			for _, adj := range tmp.adjacencies {
				triple.addAdjacency(adj)
			}
			tent.addTriple(triple)
		} else if !triple.distance.Less(d) {
			triple.distance = d
			triple.adjacencies = []*Adjacency{}
			for _, adj := range tmp.adjacencies {
				triple.addAdjacency(adj)
			}
			tent.addTriple(triple)
		}
	}
	for _, isr := range r.ipv6Reachabilities {
		d := NewSpfDistance(tmp.distance.internal, tmp.distance.external)
		d.Add(NewSpfDistance(isr.metric, 0))
		if d.external > 0 {
			continue
		}
		node := NewSpfIdIpv6(isr.ipv6Prefix, isr.prefixLength)
		if paths.findTriple(node) != nil {
			continue
		}
		triple := tent.findOrNewTriple(node)
		if triple.distance.Equal(d) {
			for _, adj := range tmp.adjacencies {
				triple.addAdjacency(adj)
			}
			tent.addTriple(triple)
		} else if !triple.distance.Less(d) {
			triple.distance = d
			triple.adjacencies = []*Adjacency{}
			for _, adj := range tmp.adjacencies {
				triple.addAdjacency(adj)
			}
			tent.addTriple(triple)
		}
	}

STEP2:
	isis.debugPrint(level, paths, tent, &step, "STEP2")
	// rfc1195 p.57 Step2
	if len(tent.triples) == 0 {
		goto DONE
	}
	// rfc1195 p.57 Step2 1)
	tmp = tent.triples[0]
	// rfc1195 p.57 Step2 1) a)
	tentlength.internal = tmp.distance.internal
	tentlength.external = tmp.distance.external
	// rfc1195 p.57 Step2 1) b)
	tent.removeTriple(tmp)
	// rfc1195 p.57 Step2 1) c)
	paths.addTriple(tmp)
	// rfc1195 p.57 Step2 1) d)
	if level == ISIS_LEVEL_2 {
		// XXX:
	}
	// rfc1195 p.57 Step2 1) e)
	if tmp.id.idType != SPF_ID_TYPE_NODE {
		goto STEP2
	} else {
		goto STEP1
	}
DONE:
	isis.debugPrint(level, paths, tent, &step, "DONE")

	select {
	case <-cancelSpfCh:
		log.Debugf("INSERT FIB CANCELED: %s", level)
		goto CANCEL
	default:
	}

	log.Debugf("INSERT FIB HERE: %s", level)
	isis.updateRiDb(level, paths)

CANCEL:
	doneSpfCh <- struct{}{}
}

func (isis *IsisServer) debugPrint(level IsisLevel, paths, tent *spfTriples, step *int, label string) {
	log.Debugf("%s: STEP%d paths: %s", level, (*step), label)
	for _, triple := range paths.triples {
		log.Debugf("%s:     %s (%d, %d)",
			level, triple.id, triple.distance.internal, triple.distance.external)
		for _, adj := range triple.adjacencies {
			log.Debugf("%s:         %x", level, adj.systemId)
			for _, v4 := range adj.ipv4Addresses {
				log.Debugf("%s:         %08x", level, v4)
			}
			for _, v6 := range adj.ipv6Addresses {
				log.Debugf("%s:         %08x:%08x:%08x:%08x", level, v6[0], v6[1], v6[2], v6[3])
			}
			log.Debugf("%s:         %s", level, adj.circuit.name)
		}
	}
	log.Debugf("%s: STEP%d tent:", level, (*step))
	for _, triple := range tent.triples {
		log.Debugf("%s:     %s (%d, %d)",
			level, triple.id, triple.distance.internal, triple.distance.external)
		for _, adj := range triple.adjacencies {
			log.Debugf("%s:         %x", level, adj.systemId)
			for _, v4 := range adj.ipv4Addresses {
				log.Debugf("%s:         %08x", level, v4)
			}
			for _, v6 := range adj.ipv6Addresses {
				log.Debugf("%s:         %08x:%08x:%08x:%08x", level, v6[0], v6[1], v6[2], v6[3])
			}
			log.Debugf("%s:         %s", level, adj.circuit.name)
		}
	}
	(*step)++
}

func (isis *IsisServer) updateRiDb(level IsisLevel, paths *spfTriples) {
	ipv4RiDb := make(map[[SPF_ID_KEY_LENGTH]byte]*Ipv4Ri)
	ipv6RiDb := make(map[[SPF_ID_KEY_LENGTH]byte]*Ipv6Ri)
	for _, triple := range paths.triples {
		if triple.id.idType == SPF_ID_TYPE_IPV4 {
			ipv4Ri := &Ipv4Ri{
				prefixAddress: triple.id.ipv4PrefixAddress,
				prefixLength:  triple.id.ipv4PrefixLength,
				nexthops:      make([]*Ipv4Nh, 0),
				metric:        triple.distance.internal,
			}
			for _, adj := range triple.adjacencies {
				var nha *uint32
				var nhc *Circuit
				for _, v4 := range adj.ipv4Addresses {
					if nha == nil {
						nha = &v4
						nhc = adj.circuit
					}
				}
				if nha != nil {
					ipv4Nh := &Ipv4Nh{
						nexthopAddress:   *nha,
						nexthopInterface: nhc,
					}
					ipv4Ri.nexthops = append(ipv4Ri.nexthops, ipv4Nh)
				}
			}
			ipv4RiDb[triple.id.key()] = ipv4Ri
		}
		if triple.id.idType == SPF_ID_TYPE_IPV6 {
			ipv6Ri := &Ipv6Ri{
				prefixAddress: [4]uint32{
					triple.id.ipv6PrefixAddress[0],
					triple.id.ipv6PrefixAddress[1],
					triple.id.ipv6PrefixAddress[2],
					triple.id.ipv6PrefixAddress[3],
				},
				prefixLength: triple.id.ipv6PrefixLength,
				nexthops:     make([]*Ipv6Nh, 0),
				metric:       triple.distance.internal,
			}
			for _, adj := range triple.adjacencies {
				var nha *[4]uint32
				var nhc *Circuit
				for _, v6 := range adj.ipv6Addresses {
					if nha == nil {
						nha = &v6
						nhc = adj.circuit
					}
				}
				if nha != nil {
					ipv6Nh := &Ipv6Nh{
						nexthopAddress:   *nha,
						nexthopInterface: nhc,
					}
					ipv6Ri.nexthops = append(ipv6Ri.nexthops, ipv6Nh)
				}
			}
			ipv6RiDb[triple.id.key()] = ipv6Ri
		}
	}
	isis.lock.Lock()
	isis.ipv4RiDb[level] = ipv4RiDb
	isis.ipv6RiDb[level] = ipv6RiDb
	isis.lock.Unlock()
}

func (isis *IsisServer) routeCalculator(level IsisLevel, doCh chan struct{}, doneCh chan struct{}) {
	log.Debugf("enter: %s", level)
	defer log.Debugf("exit: %s", level)
	for {
		<-doCh
		cancelSpfCh := make(chan struct{}, 1)
		doneSpfCh := make(chan struct{})
		go isis.spf(level, cancelSpfCh, doneSpfCh)
		select {
		case <-doCh:
			doCh <- struct{}{}
			log.Infof("REDO: %s", level)
			cancelSpfCh <- struct{}{}
			<-doneSpfCh
			select {
			case <-cancelSpfCh:
				log.Infof("XXX CANCEL SPF CH CLEAR XXX: %s", level)
			default:
			}
			goto REDO
		case <-doneSpfCh:
			log.Infof("DONE: %s", level)
		}
	REDO:
		doneCh <- struct{}{}
	}
}

var decisionChSendCount int
var decisionChSendCountLock sync.RWMutex

func (isis *IsisServer) decisionChSend(msg *DecisionChMsg) {
	go func() {
		decisionChSendCountLock.Lock()
		decisionChSendCount++
		decisionChSendCountLock.Unlock()
		log.Debugf("decisionChSend[%d]: begin", decisionChSendCount)
		isis.decisionCh <- msg
		log.Debugf("decisionChSend[%d]: end", decisionChSendCount)
	}()
}

func (isis *IsisServer) decisionProcess() {
	log.Debugf("enter")
	defer log.Debugf("exit")
	var doCh [ISIS_LEVEL_NUM]chan struct{}
	var doneCh [ISIS_LEVEL_NUM]chan struct{}
	for _, level := range ISIS_LEVEL_ALL {
		doCh[level] = make(chan struct{}, 8)
		doneCh[level] = make(chan struct{})
		go isis.routeCalculator(level, doCh[level], doneCh[level])
	}
	for {
		var redo bool
		var level1Done bool
		var level2Done bool
		msg := <-isis.decisionCh
		redo = false
	REDO:
		switch msg.msgType {
		case DECISION_CH_MSG_TYPE_DO:
			for _, level := range ISIS_LEVEL_ALL {
				doCh[level] <- struct{}{}
			}
			if redo {
				if !level1Done {
					<-doneCh[ISIS_LEVEL_1]
				}
				if !level2Done {
					<-doneCh[ISIS_LEVEL_2]
				}
			}
			level1Done = false
			level2Done = false
			for !level1Done || !level2Done {
				select {
				case <-doneCh[ISIS_LEVEL_1]:
					level1Done = true
				case <-doneCh[ISIS_LEVEL_2]:
					level2Done = true
				case msg = <-isis.decisionCh:
					redo = true
					goto REDO
				}
			}
		case DECISION_CH_MSG_TYPE_EXIT:
			goto EXIT
		}
	}
EXIT:
}
