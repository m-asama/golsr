package server

import (
	"bytes"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/m-asama/golsr/pkg/isis/packet"
)

func (circuit *Circuit) sendLs(lsp *packet.LsPdu) {
	log.Debugf("%s", circuit.name)

	if lsp.SequenceNumber == 0 || !circuit.ready() {
		log.Debugf("%s: lsp.SequenceNumber == 0 || !circuit.ready()", circuit.name)
		return
	}

	//circuit.sendPdu(lsp)
	circuit.lsSenderCh <- lsp
}

func (circuit *Circuit) receiveLs(pdu *packet.LsPdu, lanAddress []byte) {
	levelstr := "???"
	switch pdu.PduType() {
	case packet.PDU_TYPE_LEVEL1_LSP:
		levelstr = "L1"
	case packet.PDU_TYPE_LEVEL2_LSP:
		levelstr = "L2"
	}
	log.Debugf("%s %s %x %d", circuit.name, levelstr, pdu.LspId(), pdu.SequenceNumber)

	if !circuit.ready() {
		log.Debugf("%s: !circuit.ready()", circuit.name)
		return
	}

	if !pdu.BaseValid() {
		log.Debugf("%s: !pdu.BaseValid()", circuit.name)
		return
	}

	// iso10589 p.34 7.3.15.1 a) 2)
	if circuit.level1Only() && pdu.PduType() == packet.PDU_TYPE_LEVEL2_LSP {
		log.Debugf("%s: L1 system receive L2 LSP", circuit.name)
		return
	}

	// iso10589 p.34 7.3.15.1 a) 3)
	if circuit.level2Only() && pdu.PduType() == packet.PDU_TYPE_LEVEL1_LSP {
		log.Debugf("%s: L2 system receive L1 LSP", circuit.name)
		return
	}

	var adjacency *Adjacency
	switch pdu.PduType() {
	case packet.PDU_TYPE_LEVEL1_LSP:
		adjacency = circuit.findAdjacency(lanAddress, packet.CIRCUIT_TYPE_LEVEL1_ONLY)
	case packet.PDU_TYPE_LEVEL2_LSP:
		adjacency = circuit.findAdjacency(lanAddress, packet.CIRCUIT_TYPE_LEVEL2_ONLY)
	}
	if adjacency == nil {
		adjacency = circuit.findAdjacency(lanAddress, packet.CIRCUIT_TYPE_BOTH_LEVEL1_AND_LEVEL2)
	}
	if adjacency == nil {
		log.Debugf("%s: adjacency not found", circuit.name)
		return
	}

	// iso10589 p.34 7.3.15.1 a) 6)
	if circuit.configBcast() &&
		!bytes.Equal(lanAddress, adjacency.lanAddress) {
		log.Debugf("%s: adjacency lan address mismatch", circuit.name)
		return
	}
	if pdu.PduType() == packet.PDU_TYPE_LEVEL1_LSP &&
		!adjacency.level1() {
		log.Debugf("%s: adjacency level(1) mismatch", circuit.name)
		return
	}
	if pdu.PduType() == packet.PDU_TYPE_LEVEL2_LSP &&
		!adjacency.level2() {
		log.Debugf("%s: adjacency level(2) mismatch", circuit.name)
		return
	}

	// iso10589 p.35 7.3.15.1 a) 7), 8)

	var isType packet.IsType
	switch pdu.PduType() {
	case packet.PDU_TYPE_LEVEL1_LSP:
		isType = packet.IS_TYPE_LEVEL1_IS
	case packet.PDU_TYPE_LEVEL2_LSP:
		isType = packet.IS_TYPE_LEVEL2_IS
	default:
		return
	}
	currentLs := circuit.isis.lookupLsp(isType, pdu.LspId())
	if pdu.RemainingLifetime == 0 {
		// iso10589 p.35 7.3.15.1 b)
		log.Debugf("%s: p.35 b)", circuit.name)
		circuit.networkWidePurge(pdu, currentLs)
	} else if bytes.Equal(pdu.LspId()[0:packet.SYSTEM_ID_LENGTH], circuit.isis.systemId) {
		if currentLs == nil || !currentLs.origin {
			// iso10589 p.35 7.3.15.1 c)
			log.Debugf("%s: p.35 c)", circuit.name)
			circuit.networkWidePurge(pdu, currentLs)
		} else {
			// iso10589 p.35 7.3.15.1 d)
			log.Debugf("%s: p.35 d)", circuit.name)
			currentLs.pdu.SequenceNumber++
			currentLs.pdu.RemainingLifetime = circuit.isis.lspLifetime()
			circuit.isis.setSrmFlagAll(currentLs)
		}
	} else {
		// iso10589 p.35 7.3.15.1 e)
		if currentLs == nil || pdu.SequenceNumber > currentLs.pdu.SequenceNumber {
			// iso10589 p.35 7.3.15.1 e) 1)
			log.Debugf("%s: p.35 e) 1)", circuit.name)
			if currentLs == nil {
				log.Debugf("%s: currentLs == nil", circuit.name)
			} else {
				log.Debugf("%s: rcv.SeqNum = %d loc.SeqNum = %d",
					circuit.name, pdu.SequenceNumber, currentLs.pdu.SequenceNumber)
			}
			ls := circuit.isis.insertLsp(pdu, false, nil)
			circuit.isis.setSrmFlagOtherThan(ls, circuit)
			circuit.isis.clearSrmFlag(ls, circuit)
			if !circuit.configBcast() {
				circuit.isis.setSsnFlag(ls, circuit)
			}
		} else if pdu.SequenceNumber == currentLs.pdu.SequenceNumber {
			// iso10589 p.36 7.3.15.1 e) 2)
			log.Debugf("%s: p.35 e) 2)", circuit.name)
			circuit.isis.clearSrmFlag(currentLs, circuit)
			if !circuit.configBcast() {
				circuit.isis.setSsnFlag(currentLs, circuit)
			}
		} else if pdu.SequenceNumber < currentLs.pdu.SequenceNumber {
			// iso10589 p.35 7.3.15.1 e) 3)
			log.Debugf("%s: p.35 e) 3)", circuit.name)
			circuit.isis.setSrmFlag(currentLs, circuit)
			circuit.isis.clearSsnFlag(currentLs, circuit)
		} else {
			log.Debugf("%s: p.35 e) else", circuit.name)
		}
	}

	//circuit.isis.checkFlags()
	go circuit.isis.scheduleHandleFlags()
}

func (circuit *Circuit) networkWidePurge(pdu *packet.LsPdu, currentLs *Ls) {
	// iso10589 p.40 7.3.16.4
	if currentLs == nil {
		// iso10589 p.41 7.3.16.4 a)
		// send an acknowledgement of the LSP on circuit C, but
		// shall not retain the LSP after the acknowledgement has been sent.
		lsps := make([]*packet.LsPdu, 1)
		lsps[0] = pdu
		var pduType packet.PduType
		pduType = packet.PDU_TYPE_LEVEL1_PSNP
		if pdu.PduType() == packet.PDU_TYPE_LEVEL2_LSP {
			pduType = packet.PDU_TYPE_LEVEL2_PSNP
		}
		circuit.sendPsn(pduType, lsps)
		timeNow := time.Now()
		ls := circuit.isis.insertLsp(pdu, false, nil)
		ls.expired = &timeNow
	} else if !currentLs.origin {
		// iso10589 p.41 7.3.16.4 b)
		if pdu.SequenceNumber > currentLs.pdu.SequenceNumber ||
			currentLs.pdu.RemainingLifetime != 0 {
			// iso10589 p.41 7.3.16.4 b) 1)
			timeNow := time.Now()
			ls := circuit.isis.insertLsp(pdu, false, nil)
			ls.expired = &timeNow
			circuit.isis.setSrmFlagOtherThan(ls, circuit)
			circuit.isis.clearSrmFlag(ls, circuit)
			if !circuit.configBcast() {
				circuit.isis.setSsnFlag(ls, circuit)
			}
			circuit.isis.clearSsnFlagOtherThan(ls, circuit)
		} else if pdu.SequenceNumber == currentLs.pdu.SequenceNumber &&
			currentLs.pdu.RemainingLifetime == 0 {
			// iso10589 p.41 7.3.16.4 b) 2)
			circuit.isis.clearSrmFlag(currentLs, circuit)
			if !circuit.configBcast() {
				circuit.isis.setSsnFlag(currentLs, circuit)
			}
		} else if pdu.SequenceNumber < currentLs.pdu.SequenceNumber {
			// iso10589 p.41 7.3.16.4 b) 3)
			circuit.isis.setSrmFlag(currentLs, circuit)
			circuit.isis.clearSsnFlag(currentLs, circuit)
		}
	} else {
		// iso10589 p.41 7.3.16.4 c)
		currentLs.pdu.SequenceNumber++
		currentLs.pdu.RemainingLifetime = circuit.isis.lspLifetime()
		circuit.isis.setSrmFlagAll(currentLs)
	}
}
