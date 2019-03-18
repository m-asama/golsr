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
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/m-asama/golsr/pkg/isis/packet"
)

func (circuit *Circuit) sendLs(lsp *packet.LsPdu) {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)

	if lsp.SequenceNumber == 0 || !circuit.ready() {
		return
	}

	circuit.lsSenderCh <- lsp
}

func (circuit *Circuit) receiveLs(pdu *packet.LsPdu, lanAddress [packet.SYSTEM_ID_LENGTH]byte) {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)

	if !circuit.ready() {
		return
	}

	if !pdu.BaseValid() {
		return
	}

	// iso10589 p.34 7.3.15.1 a) 2)
	if circuit.level1Only() && pdu.PduType() == packet.PDU_TYPE_LEVEL2_LSP {
		return
	}

	// iso10589 p.34 7.3.15.1 a) 3)
	if circuit.level2Only() && pdu.PduType() == packet.PDU_TYPE_LEVEL1_LSP {
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
		return
	}

	// iso10589 p.34 7.3.15.1 a) 6)
	if circuit.configBcast() &&
		!bytes.Equal(lanAddress[:], adjacency.lanAddress[:]) {
		return
	}
	if pdu.PduType() == packet.PDU_TYPE_LEVEL1_LSP &&
		!adjacency.level1() {
		return
	}
	if pdu.PduType() == packet.PDU_TYPE_LEVEL2_LSP &&
		!adjacency.level2() {
		return
	}

	// iso10589 p.35 7.3.15.1 a) 7), 8)

	var level IsisLevel
	switch pdu.PduType() {
	case packet.PDU_TYPE_LEVEL1_LSP:
		level = ISIS_LEVEL_1
	case packet.PDU_TYPE_LEVEL2_LSP:
		level = ISIS_LEVEL_2
	default:
		return
	}
	currentLs := circuit.isis.lookupLsp(level, pdu.LspId())
	lspId := pdu.LspId()
	if pdu.RemainingLifetime == 0 {
		// iso10589 p.35 7.3.15.1 b)
		circuit.networkWidePurge(pdu, currentLs)
	} else if bytes.Equal(lspId[0:packet.SYSTEM_ID_LENGTH], circuit.isis.systemId[0:packet.SYSTEM_ID_LENGTH]) {
		if currentLs == nil || !currentLs.origin {
			// iso10589 p.35 7.3.15.1 c)
			circuit.networkWidePurge(pdu, currentLs)
		} else {
			// iso10589 p.35 7.3.15.1 d)
			currentLs.pdu.SequenceNumber++
			currentLs.pdu.RemainingLifetime = circuit.isis.lspLifetime()
			currentLs.pdu.SetChecksum()
			circuit.isis.setSrmFlagAll(currentLs)
		}
	} else {
		// iso10589 p.35 7.3.15.1 e)
		if currentLs == nil || pdu.SequenceNumber > currentLs.pdu.SequenceNumber {
			// iso10589 p.35 7.3.15.1 e) 1)
			ls := circuit.isis.insertLsp(pdu, false, nil)
			circuit.isis.setSrmFlagOtherThan(ls, circuit)
			circuit.isis.clearSrmFlag(ls, circuit)
			if !circuit.configBcast() {
				circuit.isis.setSsnFlag(ls, circuit)
			}
		} else if pdu.SequenceNumber == currentLs.pdu.SequenceNumber {
			// iso10589 p.36 7.3.15.1 e) 2)
			circuit.isis.clearSrmFlag(currentLs, circuit)
			if !circuit.configBcast() {
				circuit.isis.setSsnFlag(currentLs, circuit)
			}
		} else if pdu.SequenceNumber < currentLs.pdu.SequenceNumber {
			// iso10589 p.35 7.3.15.1 e) 3)
			circuit.isis.setSrmFlag(currentLs, circuit)
			circuit.isis.clearSsnFlag(currentLs, circuit)
		}
	}

	go circuit.isis.scheduleHandleFlags()
}

func (circuit *Circuit) networkWidePurge(pdu *packet.LsPdu, currentLs *Ls) {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)
	// iso10589 p.40 7.3.16.4
	if currentLs == nil {
		// iso10589 p.41 7.3.16.4 a)
		// send an acknowledgement of the LSP on circuit C, but
		// shall not retain the LSP after the acknowledgement has been sent.
		lsps := make([]*packet.LsPdu, 1)
		lsps[0] = pdu
		var pduType packet.PduType
		switch pdu.PduType() {
		case packet.PDU_TYPE_LEVEL1_LSP:
			pduType = packet.PDU_TYPE_LEVEL1_PSNP
		case packet.PDU_TYPE_LEVEL2_LSP:
			pduType = packet.PDU_TYPE_LEVEL2_PSNP
		default:
			return
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
		currentLs.pdu.SetChecksum()
		circuit.isis.setSrmFlagAll(currentLs)
	}
}
