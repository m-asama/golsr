package server

import (
	"bytes"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/m-asama/golsr/pkg/isis/packet"
)

func (circuit *Circuit) sendCsnInterval() time.Duration {
	interval := *circuit.ifConfig.Config.CsnpInterval
	return time.Duration(interval)
}

func (circuit *Circuit) sendCsn(pduType packet.PduType) {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)

	lsps := make([]*packet.LsPdu, 0)

	var lsDb []*Ls
	switch pduType {
	case packet.PDU_TYPE_LEVEL1_CSNP:
		lsDb = circuit.isis.lsDb[ISIS_LEVEL_1]
	case packet.PDU_TYPE_LEVEL2_CSNP:
		lsDb = circuit.isis.lsDb[ISIS_LEVEL_2]
	}
	for _, ls := range lsDb {
		if ls.pdu.RemainingLifetime == 0 {
			continue
		}
		lsps = append(lsps, ls.pdu)
	}

	startLspId := [packet.LSP_ID_LENGTH]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	endLspId := [packet.LSP_ID_LENGTH]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	lspEntriesTlv, _ := packet.NewLspEntriesTlv()
	for _, lsp := range lsps {
		lspEntry, _ := packet.NewLspEntriesLspEntry(lsp.LspId())
		lspEntry.RemainingLifetime = lsp.RemainingLifetime
		lspEntry.LspSeqNum = lsp.SequenceNumber
		lspEntry.Checksum = lsp.Checksum
		lspEntriesTlv.AddLspEntry(lspEntry)
	}

	var sourceId [packet.NEIGHBOUR_ID_LENGTH]byte
	copy(sourceId[0:packet.SYSTEM_ID_LENGTH], circuit.isis.systemId[0:packet.SYSTEM_ID_LENGTH])
	csn, _ := packet.NewSnPdu(pduType)
	csn.SetSourceId(sourceId)
	csn.SetStartLspId(startLspId)
	csn.SetEndLspId(endLspId)
	csn.AddLspEntriesTlv(lspEntriesTlv)

	circuit.sendPdu(csn)
}

func (circuit *Circuit) sendPsn(pduType packet.PduType, lsps []*packet.LsPdu) {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)

	lspEntriesTlv, _ := packet.NewLspEntriesTlv()
	for _, lsp := range lsps {
		lspEntry, _ := packet.NewLspEntriesLspEntry(lsp.LspId())
		lspEntry.RemainingLifetime = lsp.RemainingLifetime
		lspEntry.LspSeqNum = lsp.SequenceNumber
		lspEntry.Checksum = lsp.Checksum
		lspEntriesTlv.AddLspEntry(lspEntry)
	}

	var sourceId [packet.NEIGHBOUR_ID_LENGTH]byte
	copy(sourceId[0:packet.SYSTEM_ID_LENGTH], circuit.isis.systemId[0:packet.SYSTEM_ID_LENGTH])
	psn, _ := packet.NewSnPdu(pduType)
	psn.SetSourceId(sourceId)
	psn.AddLspEntriesTlv(lspEntriesTlv)

	circuit.snSenderCh <- psn
}

func (circuit *Circuit) receiveSn(pdu *packet.SnPdu, lanAddress [packet.SYSTEM_ID_LENGTH]byte) {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)

	if !circuit.ready() {
		return
	}

	if !pdu.BaseValid() {
		return
	}

	// iso10589 p.36 7.3.15.2 a) 2)
	if circuit.level1Only() &&
		(pdu.PduType() == packet.PDU_TYPE_LEVEL2_PSNP || pdu.PduType() == packet.PDU_TYPE_LEVEL2_CSNP) {
		return
	}

	// iso10589 p.36 7.3.15.2 a) 3)
	if circuit.level2Only() &&
		(pdu.PduType() == packet.PDU_TYPE_LEVEL1_PSNP || pdu.PduType() == packet.PDU_TYPE_LEVEL1_CSNP) {
		return
	}

	if circuit.configBcast() {
		if (pdu.PduType() == packet.PDU_TYPE_LEVEL1_PSNP || pdu.PduType() == packet.PDU_TYPE_LEVEL1_CSNP) &&
			!circuit.designated(ISIS_LEVEL_1) {
			return
		}
		if (pdu.PduType() == packet.PDU_TYPE_LEVEL2_PSNP || pdu.PduType() == packet.PDU_TYPE_LEVEL2_CSNP) &&
			!circuit.designated(ISIS_LEVEL_2) {
			return
		}
	}

	var adjacency *Adjacency
	switch pdu.PduType() {
	case packet.PDU_TYPE_LEVEL1_PSNP, packet.PDU_TYPE_LEVEL1_CSNP:
		adjacency = circuit.findAdjacency(lanAddress, packet.CIRCUIT_TYPE_LEVEL1_ONLY)
	case packet.PDU_TYPE_LEVEL2_PSNP, packet.PDU_TYPE_LEVEL2_CSNP:
		adjacency = circuit.findAdjacency(lanAddress, packet.CIRCUIT_TYPE_LEVEL2_ONLY)
	}
	if adjacency == nil {
		adjacency = circuit.findAdjacency(lanAddress, packet.CIRCUIT_TYPE_BOTH_LEVEL1_AND_LEVEL2)
	}
	if adjacency == nil {
		return
	}

	if circuit.configBcast() &&
		!bytes.Equal(lanAddress[:], adjacency.lanAddress[:]) {
		return
	}
	if (pdu.PduType() == packet.PDU_TYPE_LEVEL1_PSNP || pdu.PduType() == packet.PDU_TYPE_LEVEL1_CSNP) &&
		!adjacency.level1() {
		return
	}
	if (pdu.PduType() == packet.PDU_TYPE_LEVEL2_PSNP || pdu.PduType() == packet.PDU_TYPE_LEVEL2_CSNP) &&
		!adjacency.level2() {
		return
	}

	// iso10589 p.37 7.3.15.2 a) 7), 8)

	// iso10589 p.37 7.3.15.2 b)
	lspEntriesTlvs, _ := pdu.LspEntriesTlvs()
	for _, lspEntriesTlv := range lspEntriesTlvs {
		for _, lspEntry := range lspEntriesTlv.LspEntries() {
			circuit.handleLspEntry(pdu.PduType(), lspEntry.LspId(), lspEntry.LspSeqNum,
				lspEntry.RemainingLifetime, lspEntry.Checksum)
		}
	}

	// iso10589 p.37 7.3.15.2 c)
	if pdu.PduType() == packet.PDU_TYPE_LEVEL1_CSNP || pdu.PduType() == packet.PDU_TYPE_LEVEL2_CSNP {
		// XXX
	}

	go circuit.isis.scheduleHandleFlags()
}

func (circuit *Circuit) handleLspEntry(pduType packet.PduType, lspId [packet.LSP_ID_LENGTH]byte, lspSeqNum uint32,
	remainingLifetime, checksum uint16) {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)
	// iso10589 p.37 7.3.15.2 b) 1)
	var level IsisLevel
	switch pduType {
	case packet.PDU_TYPE_LEVEL1_PSNP:
		level = ISIS_LEVEL_1
	case packet.PDU_TYPE_LEVEL2_PSNP:
		level = ISIS_LEVEL_2
	default:
		log.Infof("pdu type invalid")
		return
	}
	currentLs := circuit.isis.lookupLsp(level, lspId)
	if currentLs == nil {
		// iso10589 p.37 7.3.15.2 b) 5)
		if remainingLifetime != 0 &&
			checksum != 0 &&
			lspSeqNum != 0 {
			var lsPduType packet.PduType
			switch pduType {
			case packet.PDU_TYPE_LEVEL1_PSNP:
				lsPduType = packet.PDU_TYPE_LEVEL1_LSP
			case packet.PDU_TYPE_LEVEL2_PSNP:
				lsPduType = packet.PDU_TYPE_LEVEL2_LSP
			}
			lsp, _ := packet.NewLsPdu(lsPduType)
			lsp.SetLspId(lspId)
			ls := circuit.isis.insertLsp(lsp, false, nil)
			circuit.isis.setSsnFlag(ls, circuit)
		}
	} else if lspSeqNum == currentLs.pdu.SequenceNumber {
		// iso10589 p.37 7.3.15.2 b) 2)
		if !circuit.configBcast() {
			circuit.isis.clearSrmFlag(currentLs, circuit)
		}
	} else if lspSeqNum < currentLs.pdu.SequenceNumber {
		// iso10589 p.37 7.3.15.2 b) 3)
		circuit.isis.clearSsnFlag(currentLs, circuit)
		circuit.isis.setSrmFlag(currentLs, circuit)
	} else if lspSeqNum > currentLs.pdu.SequenceNumber {
		// iso10589 p.37 7.3.15.2 b) 4)
		circuit.isis.setSsnFlag(currentLs, circuit)
		if !circuit.configBcast() {
			circuit.isis.clearSrmFlag(currentLs, circuit)
		}
	}
}
