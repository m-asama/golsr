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
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/m-asama/golsr/pkg/isis/packet"
)

func (isis *IsisServer) srmFlag(ls *Ls, circuit *Circuit) bool {
	log.Debugf("enter: lspid=%x circuit=%s", ls.pdu.LspId(), circuit.name)
	defer log.Debugf("exit: lspid=%x circuit=%s", ls.pdu.LspId(), circuit.name)
	_, ok := ls.srmFlags[circuit.ifIndex()]
	if ok {
		return true
	}
	return false
}

func (isis *IsisServer) setSrmFlag(ls *Ls, circuit *Circuit) {
	log.Debugf("enter: lspid=%x circuit=%s", ls.pdu.LspId(), circuit.name)
	defer log.Debugf("exit: lspid=%x circuit=%s", ls.pdu.LspId(), circuit.name)
	if ls.pdu.SequenceNumber == 0 {
		log.Debugf("ls.pdu.SequenceNumber == 0")
		return
	}
	if !circuit.ready() {
		log.Debugf("!circuit.ready()")
		return
	}
	ls.srmFlags[circuit.ifIndex()] = nil
}

func (isis *IsisServer) setSrmFlagAll(ls *Ls) {
	log.Debugf("enter: lspid=%x", ls.pdu.LspId())
	defer log.Debugf("exit: lspid=%x", ls.pdu.LspId())
	if ls.pdu.SequenceNumber == 0 {
		return
	}
	for _, cirtmp := range isis.circuitDb {
		if !cirtmp.ready() {
			continue
		}
		ls.srmFlags[cirtmp.ifIndex()] = nil
	}
}

func (isis *IsisServer) setSrmFlagOtherThan(ls *Ls, circuit *Circuit) {
	log.Debugf("enter: lspid=%x circuit=%s", ls.pdu.LspId(), circuit.name)
	defer log.Debugf("exit: lspid=%x circuit=%s", ls.pdu.LspId(), circuit.name)
	if ls.pdu.SequenceNumber == 0 {
		return
	}
	for _, cirtmp := range isis.circuitDb {
		if !cirtmp.ready() {
			continue
		}
		if cirtmp.ifIndex() == circuit.ifIndex() {
			continue
		}
		ls.srmFlags[cirtmp.ifIndex()] = nil
	}
}

func (isis *IsisServer) setSrmFlagForCircuit(circuit *Circuit) {
	log.Debugf("enter: circuit=%s", circuit.name)
	defer log.Debugf("exit: circuit=%s", circuit.name)
	isis.lock.Lock()
	defer isis.lock.Unlock()
	for _, level := range ISIS_LEVEL_ALL {
		for _, lstmp := range isis.lsDb[level] {
			isis.setSrmFlag(lstmp, circuit)
		}
	}
}

func (isis *IsisServer) clearSrmFlag(ls *Ls, circuit *Circuit) {
	log.Debugf("enter: lspid=%x circuit=%s", ls.pdu.LspId(), circuit.name)
	defer log.Debugf("exit: lspid=%x circuit=%s", ls.pdu.LspId(), circuit.name)
	delete(ls.srmFlags, circuit.ifIndex())
}

func (isis *IsisServer) ssnFlag(ls *Ls, circuit *Circuit) bool {
	log.Debugf("enter: lspid=%x circuit=%s", ls.pdu.LspId(), circuit.name)
	defer log.Debugf("exit: lspid=%x circuit=%s", ls.pdu.LspId(), circuit.name)
	_, ok := ls.ssnFlags[circuit.ifIndex()]
	if ok {
		return true
	}
	return false
}

func (isis *IsisServer) setSsnFlag(ls *Ls, circuit *Circuit) {
	log.Debugf("enter: lspid=%x circuit=%s", ls.pdu.LspId(), circuit.name)
	defer log.Debugf("exit: lspid=%x circuit=%s", ls.pdu.LspId(), circuit.name)
	if !circuit.ready() {
		log.Debugf("!circuit.ready()")
		return
	}
	ls.ssnFlags[circuit.ifIndex()] = nil
}

func (isis *IsisServer) clearSsnFlag(ls *Ls, circuit *Circuit) {
	log.Debugf("enter: lspid=%x circuit=%s", ls.pdu.LspId(), circuit.name)
	defer log.Debugf("exit: lspid=%x circuit=%s", ls.pdu.LspId(), circuit.name)
	delete(ls.ssnFlags, circuit.ifIndex())
}

func (isis *IsisServer) clearSsnFlagOtherThan(ls *Ls, circuit *Circuit) {
	log.Debugf("enter: lspid=%x circuit=%s", ls.pdu.LspId(), circuit.name)
	defer log.Debugf("exit: lspid=%x circuit=%s", ls.pdu.LspId(), circuit.name)
	for _, cirtmp := range isis.circuitDb {
		if cirtmp.ifIndex() == circuit.ifIndex() {
			continue
		}
		delete(ls.ssnFlags, cirtmp.ifIndex())
	}
}

func (isis *IsisServer) rescheduleHandleFlags(interval uint16) {
	log.Debugf("enter")
	defer log.Debugf("exit")
	time.Sleep(time.Second * time.Duration(interval))
	isis.lock.Lock()
	defer isis.lock.Unlock()
	retrans := isis.handleSrmFlags()
	if len(retrans) > 0 {
		for interval, _ := range retrans {
			go isis.rescheduleHandleFlags(interval)
		}
	}
}

func (isis *IsisServer) scheduleHandleFlags() {
	log.Debugf("enter")
	defer log.Debugf("exit")
	time.Sleep(33 * time.Millisecond)
	isis.lock.Lock()
	defer isis.lock.Unlock()
	retrans := isis.handleSrmFlags()
	isis.handleSsnFlags()
	if len(retrans) > 0 {
		for interval, _ := range retrans {
			go isis.rescheduleHandleFlags(interval)
		}
	}
}

func (isis *IsisServer) handleSrmFlags() map[uint16]bool {
	log.Debugf("enter")
	defer log.Debugf("exit")
	retrans := make(map[uint16]bool)
	for _, level := range ISIS_LEVEL_ALL {
		for _, ls := range isis.lsDb[level] {
			for ifitmp, sentOld := range ls.srmFlags {
				circuit := isis.findCircuitByIfIndex(ifitmp)
				if circuit == nil {
					continue
				}
				interval := circuit.lspRetransmitInterval()
				thresh := time.Now()
				thresh = thresh.Add(-1 * time.Second * time.Duration(interval))
				thresh = thresh.Add(33 * time.Millisecond)
				if sentOld != nil &&
					sentOld.After(thresh) {
					continue
				}
				sentNew := time.Now()
				circuit.sendLs(ls.pdu)
				ls.srmFlags[ifitmp] = &sentNew
				retrans[interval] = true
				if circuit.configBcast() {
					isis.clearSrmFlag(ls, circuit)
				}
			}
		}
	}
	return retrans
}

func (isis *IsisServer) handleSsnFlags() {
	for _, level := range ISIS_LEVEL_ALL {
		lsstmp := make(map[int][]*Ls)
		for _, ls := range isis.lsDb[level] {
			for ifitmp, _ := range ls.ssnFlags {
				circuit := isis.findCircuitByIfIndex(ifitmp)
				if circuit == nil {
					continue
				}
				lss, ok := lsstmp[ifitmp]
				if !ok {
					lss = make([]*Ls, 0)
				}
				lss = append(lss, ls)
				lsstmp[ifitmp] = lss
			}
		}
		for ifitmp, lss := range lsstmp {
			circuit := isis.findCircuitByIfIndex(ifitmp)
			if circuit == nil {
				continue
			}
			lsps := make([]*packet.LsPdu, len(lss))
			for i, _ := range lss {
				lsps[i] = lss[i].pdu
			}
			circuit.sendPsn(level.pduTypePsnp(), lsps)
			for _, ls := range lss {
				isis.clearSsnFlag(ls, circuit)
			}
		}
	}
}
