package server

import (
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/m-asama/golsr/pkg/isis/packet"
)

func (isis *IsisServer) srmFlag(ls *Ls, circuit *Circuit) bool {
	_, ok := ls.srmFlags[circuit.ifIndex()]
	if ok {
		return true
	}
	return false
}

func (isis *IsisServer) setSrmFlag(ls *Ls, circuit *Circuit) {
	log.Debugf("%x %s", ls.pdu.LspId(), circuit.name)
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
	log.Debugf("%x", ls.pdu.LspId())
	if ls.pdu.SequenceNumber == 0 {
		log.Debugf("ls.pdu.SequenceNumber == 0")
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
	log.Debugf("%x %s", ls.pdu.LspId(), circuit.name)
	if ls.pdu.SequenceNumber == 0 {
		log.Debugf("ls.pdu.SequenceNumber == 0")
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

func (isis *IsisServer) clearSrmFlag(ls *Ls, circuit *Circuit) {
	log.Debugf("%x %s", ls.pdu.LspId(), circuit.name)
	delete(ls.srmFlags, circuit.ifIndex())
}

func (isis *IsisServer) ssnFlag(ls *Ls, circuit *Circuit) bool {
	log.Debugf("%x %s", ls.pdu.LspId(), circuit.name)
	_, ok := ls.ssnFlags[circuit.ifIndex()]
	if ok {
		return true
	}
	return false
}

func (isis *IsisServer) setSsnFlag(ls *Ls, circuit *Circuit) {
	log.Debugf("%x %s", ls.pdu.LspId(), circuit.name)
	if !circuit.ready() {
		log.Debugf("!circuit.ready()")
		return
	}
	ls.ssnFlags[circuit.ifIndex()] = nil
}

func (isis *IsisServer) clearSsnFlag(ls *Ls, circuit *Circuit) {
	log.Debugf("%x %s", ls.pdu.LspId(), circuit.name)
	delete(ls.ssnFlags, circuit.ifIndex())
}

func (isis *IsisServer) clearSsnFlagOtherThan(ls *Ls, circuit *Circuit) {
	log.Debugf("%x %s", ls.pdu.LspId(), circuit.name)
	for _, cirtmp := range isis.circuitDb {
		if cirtmp.ifIndex() == circuit.ifIndex() {
			continue
		}
		delete(ls.ssnFlags, cirtmp.ifIndex())
	}
}

func (isis *IsisServer) rescheduleHandleFlags(interval uint16) {
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
	//log.Debugf("")
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
	retrans := make(map[uint16]bool)
	for _, ls := range isis.level1LsDb {
		for ifitmp, sentOld := range ls.srmFlags {
			circuit := isis.findCircuitByIfIndex(ifitmp)
			if circuit == nil {
				continue
			}
			interval := circuit.lspRetransmitInterval()
			thresh := time.Now().Add(-1*time.Second*time.Duration(interval) + 33*time.Millisecond)
			if sentOld != nil &&
				sentOld.Before(thresh) {
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
	for _, ls := range isis.level2LsDb {
		for ifitmp, sentOld := range ls.srmFlags {
			circuit := isis.findCircuitByIfIndex(ifitmp)
			if circuit == nil {
				continue
			}
			interval := circuit.lspRetransmitInterval()
			thresh := time.Now().Add(-1*time.Second*time.Duration(interval) + 10*time.Millisecond)
			if sentOld != nil &&
				sentOld.Before(thresh) {
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
	return retrans
}

func (isis *IsisServer) handleSsnFlags() {
	{
		l1lss := make(map[int][]*Ls)
		for _, ls := range isis.level1LsDb {
			for ifitmp, _ := range ls.ssnFlags {
				circuit := isis.findCircuitByIfIndex(ifitmp)
				if circuit == nil {
					continue
				}
				lss, ok := l1lss[ifitmp]
				if !ok {
					lss = make([]*Ls, 0)
				}
				lss = append(lss, ls)
				l1lss[ifitmp] = lss
			}
		}
		for ifitmp, lss := range l1lss {
			circuit := isis.findCircuitByIfIndex(ifitmp)
			if circuit == nil {
				continue
			}
			lsps := make([]*packet.LsPdu, len(lss))
			for i, _ := range lss {
				lsps[i] = lss[i].pdu
			}
			circuit.sendPsn(packet.PDU_TYPE_LEVEL1_PSNP, lsps)
			for _, ls := range lss {
				isis.clearSsnFlag(ls, circuit)
			}
		}
	}
	{
		l2lss := make(map[int][]*Ls)
		for _, ls := range isis.level2LsDb {
			for ifitmp, _ := range ls.ssnFlags {
				circuit := isis.findCircuitByIfIndex(ifitmp)
				if circuit == nil {
					continue
				}
				lss, ok := l2lss[ifitmp]
				if !ok {
					lss = make([]*Ls, 0)
				}
				lss = append(lss, ls)
				l2lss[ifitmp] = lss
			}
		}
		for ifitmp, lss := range l2lss {
			circuit := isis.findCircuitByIfIndex(ifitmp)
			if circuit == nil {
				continue
			}
			lsps := make([]*packet.LsPdu, len(lss))
			for i, _ := range lss {
				lsps[i] = lss[i].pdu
			}
			circuit.sendPsn(packet.PDU_TYPE_LEVEL2_PSNP, lsps)
			for _, ls := range lss {
				isis.clearSsnFlag(ls, circuit)
			}
		}
	}
}
