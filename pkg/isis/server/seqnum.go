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
	log.Debugf("%s", circuit.name)

	lsps := make([]*packet.LsPdu, 0)

	var lsDb []*Ls
	switch pduType {
	case packet.PDU_TYPE_LEVEL1_CSNP:
		lsDb = circuit.isis.level1LsDb
	case packet.PDU_TYPE_LEVEL2_CSNP:
		lsDb = circuit.isis.level2LsDb
	}
	for _, ls := range lsDb {
		if ls.pdu.RemainingLifetime == 0 {
			continue
		}
		lsps = append(lsps, ls.pdu)
	}

	startLspId := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	endLspId := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	lspEntriesTlv, _ := packet.NewLspEntriesTlv()
	for _, lsp := range lsps {
		lspEntry, _ := packet.NewLspEntriesLspEntry(lsp.LspId())
		lspEntry.RemainingLifetime = lsp.RemainingLifetime
		lspEntry.LspSeqNum = lsp.SequenceNumber
		lspEntry.Checksum = lsp.Checksum
		lspEntriesTlv.AddLspEntry(lspEntry)
	}

	csn, _ := packet.NewSnPdu(pduType)
	csn.SetSourceId(circuit.isis.systemId)
	csn.SetStartLspId(startLspId)
	csn.SetEndLspId(endLspId)
	csn.AddLspEntriesTlv(lspEntriesTlv)

	circuit.sendPdu(csn)
}

func (circuit *Circuit) sendPsn(pduType packet.PduType, lsps []*packet.LsPdu) {
	log.Debugf("%s", circuit.name)

	lspEntriesTlv, _ := packet.NewLspEntriesTlv()
	for _, lsp := range lsps {
		lspEntry, _ := packet.NewLspEntriesLspEntry(lsp.LspId())
		lspEntry.RemainingLifetime = lsp.RemainingLifetime
		lspEntry.LspSeqNum = lsp.SequenceNumber
		lspEntry.Checksum = lsp.Checksum
		lspEntriesTlv.AddLspEntry(lspEntry)
	}

	psn, _ := packet.NewSnPdu(pduType)
	psn.SetSourceId(circuit.isis.systemId)
	psn.AddLspEntriesTlv(lspEntriesTlv)

	circuit.snSenderCh <- psn
}

func (circuit *Circuit) receiveSn(pdu *packet.SnPdu, lanAddress []byte) {
	log.Debugf("%s", circuit.name)

	if !circuit.ready() {
		log.Debugf("!circuit.ready()")
		return
	}

	if !pdu.BaseValid() {
		log.Debugf("!pdu.BaseValid()")
		return
	}

	// iso10589 p.36 7.3.15.2 a) 2)
	if circuit.level1Only() &&
		(pdu.PduType() == packet.PDU_TYPE_LEVEL2_PSNP || pdu.PduType() == packet.PDU_TYPE_LEVEL2_CSNP) {
		log.Debugf("L1 system receive L2 SNP")
		return
	}

	// iso10589 p.36 7.3.15.2 a) 3)
	if circuit.level2Only() &&
		(pdu.PduType() == packet.PDU_TYPE_LEVEL1_PSNP || pdu.PduType() == packet.PDU_TYPE_LEVEL1_CSNP) {
		log.Debugf("L2 system receive L1 SNP")
		return
	}

	if circuit.configBcast() {
		if (pdu.PduType() == packet.PDU_TYPE_LEVEL1_PSNP || pdu.PduType() == packet.PDU_TYPE_LEVEL1_CSNP) &&
			!circuit.designated(ISIS_LEVEL_1) {
			log.Debugf("%s: PduType == LEVEL1_?SNP && !level1Designated()",
				circuit.name)
			return
		}
		if (pdu.PduType() == packet.PDU_TYPE_LEVEL2_PSNP || pdu.PduType() == packet.PDU_TYPE_LEVEL2_CSNP) &&
			!circuit.designated(ISIS_LEVEL_2) {
			log.Debugf("%s: PduType == LEVEL2_?SNP && !level2Designated()",
				circuit.name)
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
		log.Debugf("adjacency not found")
		return
	}

	if circuit.configBcast() &&
		!bytes.Equal(lanAddress, adjacency.lanAddress) {
		log.Debugf("adjacency lan address mismatch")
		return
	}
	if (pdu.PduType() == packet.PDU_TYPE_LEVEL1_PSNP || pdu.PduType() == packet.PDU_TYPE_LEVEL1_CSNP) &&
		!adjacency.level1() {
		log.Debugf("adjacency level(1) mismatch")
		return
	}
	if (pdu.PduType() == packet.PDU_TYPE_LEVEL2_PSNP || pdu.PduType() == packet.PDU_TYPE_LEVEL2_CSNP) &&
		!adjacency.level2() {
		log.Debugf("adjacency level(2) mismatch")
		return
	}

	// iso10589 p.37 7.3.15.2 a) 7), 8)

	// iso10589 p.37 7.3.15.2 b)
	lspEntriesTlvs, _ := pdu.LspEntriesTlvs()
	for _, lspEntriesTlv := range lspEntriesTlvs {
		for _, lspEntry := range lspEntriesTlv.LspEntries() {
			log.Debugf("%s %x %d",
				pdu.PduType(), lspEntry.LspId(), lspEntry.LspSeqNum)
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

func (circuit *Circuit) handleLspEntry(pduType packet.PduType, lspId []byte, lspSeqNum uint32,
	remainingLifetime, checksum uint16) {
	// iso10589 p.37 7.3.15.2 b) 1)
	var isType packet.IsType
	switch pduType {
	case packet.PDU_TYPE_LEVEL1_PSNP:
		isType = packet.IS_TYPE_LEVEL1_IS
	case packet.PDU_TYPE_LEVEL2_PSNP:
		isType = packet.IS_TYPE_LEVEL2_IS
	default:
		return
	}
	currentLs := circuit.isis.lookupLsp(isType, lspId)
	if currentLs == nil {
		// iso10589 p.37 7.3.15.2 b) 5)
		log.Debugf("%s: p.37 b) 5)", circuit.name)
		if remainingLifetime != 0 &&
			checksum != 0 &&
			lspSeqNum != 0 {
			log.Debugf("%s: lifetime, checksum, seqnum all zero", circuit.name)
			lsp, _ := packet.NewLsPdu(pduType)
			lsp.SetLspId(lspId)
			ls := circuit.isis.insertLsp(lsp, false, nil)
			circuit.isis.setSsnFlag(ls, circuit)
		}
	} else if lspSeqNum == currentLs.pdu.SequenceNumber {
		// iso10589 p.37 7.3.15.2 b) 2)
		log.Debugf("%s: p.37 b) 2)", circuit.name)
		if !circuit.configBcast() {
			circuit.isis.clearSrmFlag(currentLs, circuit)
		}
	} else if lspSeqNum < currentLs.pdu.SequenceNumber {
		// iso10589 p.37 7.3.15.2 b) 3)
		log.Debugf("%s: p.37 b) 3)", circuit.name)
		circuit.isis.clearSsnFlag(currentLs, circuit)
		circuit.isis.clearSrmFlag(currentLs, circuit)
	} else if lspSeqNum > currentLs.pdu.SequenceNumber {
		// iso10589 p.37 7.3.15.2 b) 4)
		log.Debugf("%s: p.37 b) 4)", circuit.name)
		circuit.isis.setSsnFlag(currentLs, circuit)
		if !circuit.configBcast() {
			circuit.isis.clearSrmFlag(currentLs, circuit)
		}
	}
}
