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

func (circuit *Circuit) sendP2pIihInterval() time.Duration {
	interval := circuit.helloInterval(ISIS_LEVEL_1)
	if circuit.helloInterval(ISIS_LEVEL_2) < interval {
		interval = circuit.helloInterval(ISIS_LEVEL_2)
	}
	return time.Duration(interval)
}

func (circuit *Circuit) sendL1lIihInterval() time.Duration {
	return time.Duration(circuit.helloInterval(ISIS_LEVEL_1))
}

func (circuit *Circuit) sendL2lIihInterval() time.Duration {
	return time.Duration(circuit.helloInterval(ISIS_LEVEL_2))
}

func (circuit *Circuit) sendLanIihInterval(level IsisLevel) time.Duration {
	switch level {
	case ISIS_LEVEL_1:
		return circuit.sendL1lIihInterval()
	case ISIS_LEVEL_2:
		return circuit.sendL2lIihInterval()
	}
	log.Infof("")
	panic("")
	return time.Duration(0)
}

func (circuit *Circuit) p2pHoldingTime() uint16 {
	holdingTime := circuit.helloHoldingTime(ISIS_LEVEL_1)
	if circuit.helloHoldingTime(ISIS_LEVEL_2) < holdingTime {
		holdingTime = circuit.helloHoldingTime(ISIS_LEVEL_2)
	}
	return holdingTime
}

func (circuit *Circuit) l1lHoldingTime() uint16 {
	return circuit.helloHoldingTime(ISIS_LEVEL_1)
}

func (circuit *Circuit) l2lHoldingTime() uint16 {
	return circuit.helloHoldingTime(ISIS_LEVEL_2)
}

func (circuit *Circuit) holdingTime(pduType packet.PduType) uint16 {
	switch pduType {
	case packet.PDU_TYPE_LEVEL1_LAN_IIHP:
		return circuit.l1lHoldingTime()
	case packet.PDU_TYPE_LEVEL2_LAN_IIHP:
		return circuit.l2lHoldingTime()
	case packet.PDU_TYPE_P2P_IIHP:
		return circuit.p2pHoldingTime()
	}
	log.Infof("")
	panic("")
	return uint16(30)
}

func (circuit *Circuit) sendIih(pduType packet.PduType) {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)

	iih, err := packet.NewIihPdu(pduType)
	if err != nil {
		log.Infof("NewIihPdu failed: %v", err)
		return
	}

	iih.CircuitType = circuit.circuitType()
	iih.SetSourceId(circuit.isis.systemId)
	iih.HoldingTime = circuit.holdingTime(pduType)

	if pduType != packet.PDU_TYPE_P2P_IIHP {
		level := pduType2level(pduType)
		iih.Priority = circuit.priority(level)
		iih.SetLanId(circuit.lanId(level))
	}

	protocolsSupportedTlv, _ := packet.NewProtocolsSupportedTlv()
	protocolsSupportedTlv.AddNlpId(packet.NLP_ID_IPV4)
	protocolsSupportedTlv.AddNlpId(packet.NLP_ID_IPV6)
	iih.SetProtocolsSupportedTlv(protocolsSupportedTlv)

	areaAddressesTlv, _ := packet.NewAreaAddressesTlv()
	for _, areaAddress := range circuit.isis.areaAddresses {
		areaAddressesTlv.AddAreaAddress(areaAddress)
	}
	iih.SetAreaAddressesTlv(areaAddressesTlv)

	if pduType != packet.PDU_TYPE_P2P_IIHP {
		isNeighboursHelloTlv, _ := packet.NewIsNeighboursHelloTlv()
		for _, adjacency := range circuit.adjacencyDb {
			if adjacency.adjState == packet.ADJ_3WAY_STATE_DOWN ||
				(pduType == packet.PDU_TYPE_LEVEL1_LAN_IIHP &&
					adjacency.adjType != ADJ_TYPE_LEVEL1_LAN) ||
				(pduType == packet.PDU_TYPE_LEVEL2_LAN_IIHP &&
					adjacency.adjType != ADJ_TYPE_LEVEL2_LAN) {
				continue
			}
			isNeighboursHelloTlv.AddLanAddress(adjacency.lanAddress)
		}
		iih.AddIsNeighboursHelloTlv(isNeighboursHelloTlv)
	}

	if pduType == packet.PDU_TYPE_P2P_IIHP {
		p2p3wayAdjacencyTlv, _ := packet.NewP2p3wayAdjacencyTlv()
		p2p3wayAdjacencyTlv.Adj3wayState = packet.ADJ_3WAY_STATE_DOWN
		p2p3wayAdjacencyTlv.ExtLocalCircuitId = circuit.extendedLocalCircuitId
		var adjacency *Adjacency
		for _, adjtmp := range circuit.adjacencyDb {
			if adjacency == nil ||
				adjtmp.holdingTime > adjacency.holdingTime {
				adjacency = adjtmp
			}
		}
		if adjacency != nil {
			p2p3wayAdjacencyTlv.Adj3wayState = adjacency.adjState
			p2p3wayAdjacencyTlv.SetNeighbourSystemId(adjacency.systemId)
			p2p3wayAdjacencyTlv.NeighExtLocalCircuitId = adjacency.extendedCircuitId
		}
		iih.SetP2p3wayAdjacencyTlv(p2p3wayAdjacencyTlv)
	}

	ipInterfaceAddressTlv, _ := packet.NewIpInterfaceAddressTlv()
	for _, ipv4Address := range circuit.ifKernel.Ipv4Addresses {
		ipInterfaceAddressTlv.AddIpAddress(ipv4Address.Address)
	}
	iih.SetIpInterfaceAddressTlv(ipInterfaceAddressTlv)

	ipv6InterfaceAddressTlv, _ := packet.NewIpv6InterfaceAddressTlv()
	llFound := false
	for _, ipv6Address := range circuit.ifKernel.Ipv6Addresses {
		if ipv6Address.ScopeLink {
			ipv6InterfaceAddressTlv.AddIpv6Address(ipv6Address.Address)
			llFound = true
		}
	}
	if !llFound {
		for _, ipv6Address := range circuit.ifKernel.Ipv6Addresses {
			ipv6InterfaceAddressTlv.AddIpv6Address(ipv6Address.Address)
		}
	}
	iih.SetIpv6InterfaceAddressTlv(ipv6InterfaceAddressTlv)

	data, err := iih.Serialize()
	if err != nil {
		log.Infof("Serialize failed: %v", err)
		return
	}
	i := len(data)
	pduLen := circuit.kernelMtu()
	if circuit.kernelBcast() {
		pduLen -= 3
	}
	for i < pduLen {
		var padLen uint8
		if i+257 <= pduLen {
			padLen = uint8(255)
			if pduLen-(i+257) < 2 {
				padLen--
			}
		} else {
			padLen = uint8(pduLen - i - 2)
		}
		padding, _ := packet.NewPaddingTlv()
		padding.SetLength(padLen)
		iih.AddPaddingTlv(padding)
		i += int(padLen) + 2
	}
	if i != pduLen {
		log.Infof("Padding failed")
		return
	}

	circuit.sendPdu(iih)
}

func (circuit *Circuit) receiveBcastIih(pdu *packet.IihPdu, remoteLanAddress [packet.SYSTEM_ID_LENGTH]byte) {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)

	if !circuit.ready() {
		return
	}

	if !pdu.BaseValid() {
		return
	}

	systemId := pdu.SourceId()

	ipv4Supported := false
	ipv6Supported := false
	protocolsSupportedTlv, err := pdu.ProtocolsSupportedTlv()
	if err != nil {
		log.Infof("get ProtocolsSupportedTlv failed: %v", err)
		return
	}
	if protocolsSupportedTlv != nil {
		protocolsSupported := protocolsSupportedTlv.ProtocolsSupported()
		for _, nlpId := range protocolsSupported {
			switch nlpId {
			case packet.NLP_ID_IPV4:
				ipv4Supported = true
			case packet.NLP_ID_IPV6:
				ipv6Supported = true
			}
		}
	}

	ipv4Addresses := make([]uint32, 0)
	ipInterfaceAddressTlv, err := pdu.IpInterfaceAddressTlv()
	if err != nil {
		log.Infof("get IpInterfaceAddressTlv failed: %v", err)
		return
	}
	if ipInterfaceAddressTlv != nil {
		ipv4Addresses = ipInterfaceAddressTlv.IpAddresses()
	}

	ipv6Addresses := make([][4]uint32, 0)
	ipv6InterfaceAddressTlv, err := pdu.Ipv6InterfaceAddressTlv()
	if err != nil {
		log.Infof("get Ipv6InterfaceAddressTlv failed: %v", err)
		return
	}
	if ipv6InterfaceAddressTlv != nil {
		ipv6Addresses = ipv6InterfaceAddressTlv.Ipv6Addresses()
	}

	areaAddressesTlv, err := pdu.AreaAddressesTlv()
	if err != nil {
		log.Infof("get AreaAddressesTlv failed: %v", err)
		return
	}
	areaAddresses := areaAddressesTlv.AreaAddresses()

	var adjType AdjType
	var adjUsage AdjUsage
	switch pdu.PduType() {
	case packet.PDU_TYPE_LEVEL1_LAN_IIHP:
		// iso10589 p.60 8.4.2.2
		if !circuit.isis.matchAreaAddresses(areaAddresses) {
			log.Infof("area address mismatch")
			return
		}
		adjType = ADJ_TYPE_LEVEL1_LAN
		adjUsage = ADJ_USAGE_LEVEL1
	case packet.PDU_TYPE_LEVEL2_LAN_IIHP:
		// iso10589 p.61 8.4.2.3
		adjType = ADJ_TYPE_LEVEL2_LAN
		adjUsage = ADJ_USAGE_LEVEL2
	}

	remoteLanAddresses := make([][packet.SYSTEM_ID_LENGTH]byte, 0)
	isNeighboursHelloTlvs, err := pdu.IsNeighboursHelloTlvs()
	if err != nil {
		log.Infof("get IsNeighboursHelloTlv failed: %v", err)
		return
	}
	if isNeighboursHelloTlvs != nil {
		for _, isNeighboursHelloTlv := range isNeighboursHelloTlvs {
			lastmp := isNeighboursHelloTlv.LanAddresses()
			for _, latmp := range lastmp {
				remoteLanAddresses = append(remoteLanAddresses, latmp)
			}
		}
	}

	adjacency := circuit.findAdjacency(remoteLanAddress, adjType)
	if adjacency != nil && bytes.Equal(adjacency.systemId[:], systemId[:]) {
		// iso10589 p.61 8.4.2.4
		adjacency.holdingTime = pdu.HoldingTime
		adjacency.priority = pdu.Priority
		adjacency.areaAddresses = areaAddresses

	} else {
		if adjacency != nil {
			circuit.removeAdjacency(remoteLanAddress, adjType)
		}
		// iso10589 p.61 8.4.2.5
		adjacency, err = NewAdjacency(circuit)
		if err != nil {
			log.Infof("NewAdjacency failed: %v", err)
			return
		}
		adjacency.adjState = packet.ADJ_3WAY_STATE_INITIALIZING
		adjacency.adjUsage = adjUsage
		adjacency.adjType = adjType
		adjacency.ipv4Supported = ipv4Supported
		adjacency.ipv6Supported = ipv6Supported
		adjacency.areaAddresses = areaAddresses
		adjacency.ipv4Addresses = ipv4Addresses
		adjacency.ipv6Addresses = ipv6Addresses
		adjacency.areaAddresses = areaAddresses
		adjacency.lanAddress = remoteLanAddress
		adjacency.systemId = systemId
		adjacency.priority = pdu.Priority
		adjacency.lanId = pdu.LanId()
		//adjacency.circuitId
		//adjacency.extendedCircuitId
		adjacency.holdingTime = pdu.HoldingTime
		circuit.addAdjacency(adjacency)
	}

	localLanAddress := circuit.kernelHardwareAddr()
	included := false
	for _, latmp := range remoteLanAddresses {
		if bytes.Equal(latmp[:], localLanAddress[:]) {
			included = true
		}
	}
	if included {
		if adjacency.adjState != packet.ADJ_3WAY_STATE_UP {
			log.Infof("%s: %x: %s -> ADJ_3WAY_STATE_UP", circuit.name, adjacency.lanAddress,
				adjacency.adjState)
			// iso10589 p.61 8.4.2.5.1
			adjacency.adjState = packet.ADJ_3WAY_STATE_UP
			circuit.isis.updateChSend(&UpdateChMsg{
				msgType:   UPDATE_CH_MSG_TYPE_ADJACENCY_UP,
				adjacency: adjacency,
			})
		}
	} else {
		if adjacency.adjState == packet.ADJ_3WAY_STATE_UP {
			log.Infof("%s: %x: %s -> ADJ_3WAY_STATE_INITIALIZING", circuit.name, adjacency.lanAddress,
				adjacency.adjState)
			// iso10589 p.62 8.4.5.3
			adjacency.adjState = packet.ADJ_3WAY_STATE_INITIALIZING
			circuit.isis.updateChSend(&UpdateChMsg{
				msgType:   UPDATE_CH_MSG_TYPE_ADJACENCY_DOWN,
				adjacency: adjacency,
			})
		}
	}
}

type P2pIihAction uint8

const (
	_ P2pIihAction = iota
	P2P_IIH_ACTION_NONE
	P2P_IIH_ACTION_UP
	P2P_IIH_ACTION_DOWN
	P2P_IIH_ACTION_ACCEPT
	P2P_IIH_ACTION_REJECT
)

func (circuit *Circuit) receiveP2pIih(pdu *packet.IihPdu, remoteLanAddress [packet.SYSTEM_ID_LENGTH]byte) {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)

	if !circuit.ready() {
		return
	}

	if !pdu.BaseValid() {
		return
	}

	systemId := pdu.SourceId()

	areaAddressesTlv, err := pdu.AreaAddressesTlv()
	if err != nil {
		log.Infof("get AreaAddressesTlv failed: %v", err)
		return
	}
	areaAddresses := areaAddressesTlv.AreaAddresses()

	protocolsSupportedTlv, err := pdu.ProtocolsSupportedTlv()
	if err != nil {
		log.Infof("get ProtocolsSupportedTlv failed: %v", err)
		return
	}
	ipv4Supported := false
	ipv6Supported := false
	protocolsSupported := protocolsSupportedTlv.ProtocolsSupported()
	for _, nlpId := range protocolsSupported {
		switch nlpId {
		case packet.NLP_ID_IPV4:
			ipv4Supported = true
		case packet.NLP_ID_IPV6:
			ipv6Supported = true
		}
	}

	ipInterfaceAddressTlv, err := pdu.IpInterfaceAddressTlv()
	if err != nil {
		log.Infof("get IpInterfaceAddressTlv failed: %v", err)
		return
	}
	ipv4Addresses := ipInterfaceAddressTlv.IpAddresses()

	ipv6InterfaceAddressTlv, err := pdu.Ipv6InterfaceAddressTlv()
	if err != nil {
		log.Infof("get Ipv6InterfaceAddressTlv failed: %v", err)
		return
	}
	ipv6Addresses := ipv6InterfaceAddressTlv.Ipv6Addresses()

	p2p3wayAdjacencyTlv, _ := pdu.P2p3wayAdjacencyTlv()

	var adjType AdjType
	adjType = ADJ_TYPE_P2P
	adjacency := circuit.findAdjacency(remoteLanAddress, adjType)
	if adjacency == nil {
		adjacency, err = NewAdjacency(circuit)
		if err != nil {
			log.Infof("NewAdjacency failed: %v", err)
			return
		}
		adjacency.adjState = packet.ADJ_3WAY_STATE_DOWN
		adjacency.adjUsage = ADJ_USAGE_NONE
		adjacency.adjType = adjType
		adjacency.ipv4Supported = ipv4Supported
		adjacency.ipv6Supported = ipv6Supported
		adjacency.areaAddresses = areaAddresses
		adjacency.ipv4Addresses = ipv4Addresses
		adjacency.ipv6Addresses = ipv6Addresses
		adjacency.lanAddress = remoteLanAddress
		adjacency.systemId = systemId
		//adjacency.priority
		//adjacency.lanId
		adjacency.circuitId = pdu.LocalCircuitId
		if p2p3wayAdjacencyTlv != nil {
			adjacency.extendedCircuitId = p2p3wayAdjacencyTlv.ExtLocalCircuitId
		}
		adjacency.holdingTime = pdu.HoldingTime
	}

	var action P2pIihAction
	if circuit.isis.matchAreaAddresses(areaAddresses) {
		// iso10589 p.52 8.2.5.2 a)
		if circuit.isis.level1Only() {
			// iso10589 p.53 table 5
			switch pdu.CircuitType {
			case packet.CIRCUIT_TYPE_LEVEL1_ONLY, packet.CIRCUIT_TYPE_BOTH_LEVEL1_AND_LEVEL2:
				switch adjacency.adjUsage {
				case ADJ_USAGE_NONE:
					action = P2P_IIH_ACTION_UP
					adjacency.adjState = packet.ADJ_3WAY_STATE_UP
					adjacency.adjUsage = ADJ_USAGE_LEVEL1
					circuit.addAdjacency(adjacency)
					circuit.isis.updateChSend(&UpdateChMsg{
						msgType:   UPDATE_CH_MSG_TYPE_ADJACENCY_UP,
						adjacency: adjacency,
					})
				case ADJ_USAGE_LEVEL1:
					action = P2P_IIH_ACTION_ACCEPT
				}
			case packet.CIRCUIT_TYPE_LEVEL2_ONLY:
				switch adjacency.adjUsage {
				case ADJ_USAGE_NONE:
					log.Debugf("Reject(Wrong system)")
					action = P2P_IIH_ACTION_REJECT
				case ADJ_USAGE_LEVEL1:
					log.Debugf("Down(Wrong system)")
					action = P2P_IIH_ACTION_DOWN
					adjacency.adjState = packet.ADJ_3WAY_STATE_DOWN
					circuit.removeAdjacency(remoteLanAddress, adjType)
					circuit.isis.updateChSend(&UpdateChMsg{
						msgType:   UPDATE_CH_MSG_TYPE_ADJACENCY_DOWN,
						adjacency: adjacency,
					})
				}
			}
		}
		if circuit.isis.levelAll() {
			// iso10589 p.54 table 6
			switch pdu.CircuitType {
			case packet.CIRCUIT_TYPE_LEVEL1_ONLY:
				switch adjacency.adjUsage {
				case ADJ_USAGE_NONE:
					action = P2P_IIH_ACTION_UP
					adjacency.adjState = packet.ADJ_3WAY_STATE_UP
					adjacency.adjUsage = ADJ_USAGE_LEVEL1
					circuit.addAdjacency(adjacency)
					circuit.isis.updateChSend(&UpdateChMsg{
						msgType:   UPDATE_CH_MSG_TYPE_ADJACENCY_UP,
						adjacency: adjacency,
					})
				case ADJ_USAGE_LEVEL1:
					action = P2P_IIH_ACTION_ACCEPT
				case ADJ_USAGE_LEVEL1AND2, ADJ_USAGE_LEVEL2:
					log.Debugf("Down(Wrong system)")
					action = P2P_IIH_ACTION_DOWN
					adjacency.adjState = packet.ADJ_3WAY_STATE_DOWN
					circuit.removeAdjacency(remoteLanAddress, adjType)
					circuit.isis.updateChSend(&UpdateChMsg{
						msgType:   UPDATE_CH_MSG_TYPE_ADJACENCY_DOWN,
						adjacency: adjacency,
					})
				}
			case packet.CIRCUIT_TYPE_LEVEL2_ONLY:
				switch adjacency.adjUsage {
				case ADJ_USAGE_NONE:
					action = P2P_IIH_ACTION_UP
					adjacency.adjState = packet.ADJ_3WAY_STATE_UP
					adjacency.adjUsage = ADJ_USAGE_LEVEL2
					circuit.addAdjacency(adjacency)
					circuit.isis.updateChSend(&UpdateChMsg{
						msgType:   UPDATE_CH_MSG_TYPE_ADJACENCY_UP,
						adjacency: adjacency,
					})
				case ADJ_USAGE_LEVEL1, ADJ_USAGE_LEVEL1AND2:
					log.Debugf("Down(Wrong system)")
					action = P2P_IIH_ACTION_DOWN
					adjacency.adjState = packet.ADJ_3WAY_STATE_DOWN
					circuit.removeAdjacency(remoteLanAddress, adjType)
					circuit.isis.updateChSend(&UpdateChMsg{
						msgType:   UPDATE_CH_MSG_TYPE_ADJACENCY_DOWN,
						adjacency: adjacency,
					})
				case ADJ_USAGE_LEVEL2:
					action = P2P_IIH_ACTION_ACCEPT
				}
			case packet.CIRCUIT_TYPE_BOTH_LEVEL1_AND_LEVEL2:
				switch adjacency.adjUsage {
				case ADJ_USAGE_NONE:
					action = P2P_IIH_ACTION_UP
					adjacency.adjState = packet.ADJ_3WAY_STATE_UP
					adjacency.adjUsage = ADJ_USAGE_LEVEL1AND2
					circuit.addAdjacency(adjacency)
					circuit.isis.updateChSend(&UpdateChMsg{
						msgType:   UPDATE_CH_MSG_TYPE_ADJACENCY_UP,
						adjacency: adjacency,
					})
				case ADJ_USAGE_LEVEL1, ADJ_USAGE_LEVEL2:
					log.Debugf("Down(Wrong system)")
					action = P2P_IIH_ACTION_DOWN
					adjacency.adjState = packet.ADJ_3WAY_STATE_DOWN
					circuit.removeAdjacency(remoteLanAddress, adjType)
					circuit.isis.updateChSend(&UpdateChMsg{
						msgType:   UPDATE_CH_MSG_TYPE_ADJACENCY_DOWN,
						adjacency: adjacency,
					})
				case ADJ_USAGE_LEVEL1AND2:
					action = P2P_IIH_ACTION_ACCEPT
				}
			}
		}
		if circuit.isis.level2Only() {
			// iso10589 p.54 table 7
			switch pdu.CircuitType {
			case packet.CIRCUIT_TYPE_LEVEL1_ONLY:
				switch adjacency.adjUsage {
				case ADJ_USAGE_NONE:
					log.Debugf("Reject(Wrong system)")
					action = P2P_IIH_ACTION_REJECT
				case ADJ_USAGE_LEVEL1AND2, ADJ_USAGE_LEVEL2:
					log.Debugf("Down(Wrong system)")
					action = P2P_IIH_ACTION_DOWN
					adjacency.adjState = packet.ADJ_3WAY_STATE_DOWN
					circuit.removeAdjacency(remoteLanAddress, adjType)
					circuit.isis.updateChSend(&UpdateChMsg{
						msgType:   UPDATE_CH_MSG_TYPE_ADJACENCY_DOWN,
						adjacency: adjacency,
					})
				}
			case packet.CIRCUIT_TYPE_LEVEL2_ONLY, packet.CIRCUIT_TYPE_BOTH_LEVEL1_AND_LEVEL2:
				switch adjacency.adjUsage {
				case ADJ_USAGE_NONE:
					action = P2P_IIH_ACTION_UP
					adjacency.adjState = packet.ADJ_3WAY_STATE_UP
					adjacency.adjUsage = ADJ_USAGE_LEVEL2
					circuit.addAdjacency(adjacency)
					circuit.isis.updateChSend(&UpdateChMsg{
						msgType:   UPDATE_CH_MSG_TYPE_ADJACENCY_UP,
						adjacency: adjacency,
					})
				case ADJ_USAGE_LEVEL1AND2:
					log.Debugf("Down(Wrong system)")
					action = P2P_IIH_ACTION_DOWN
					adjacency.adjState = packet.ADJ_3WAY_STATE_DOWN
					circuit.removeAdjacency(remoteLanAddress, adjType)
					circuit.isis.updateChSend(&UpdateChMsg{
						msgType:   UPDATE_CH_MSG_TYPE_ADJACENCY_DOWN,
						adjacency: adjacency,
					})
				case ADJ_USAGE_LEVEL2:
					action = P2P_IIH_ACTION_ACCEPT
				}
			}
		}
	} else {
		// iso10589 p.53 8.2.5.2 b)
		if circuit.isis.level1Only() && adjacency.adjState != packet.ADJ_3WAY_STATE_UP {
			// iso10589 p.53 8.2.5.2 b) 1)
			circuit.removeAdjacency(remoteLanAddress, adjType)
		}
		if circuit.isis.level1Only() && adjacency.adjState == packet.ADJ_3WAY_STATE_UP {
			// iso10589 p.53 8.2.5.2 b) 2)
			action = P2P_IIH_ACTION_DOWN
			circuit.removeAdjacency(remoteLanAddress, adjType)
			circuit.isis.updateChSend(&UpdateChMsg{
				msgType:   UPDATE_CH_MSG_TYPE_ADJACENCY_DOWN,
				adjacency: adjacency,
			})
		}
		if circuit.isis.level2() {
			// iso10589 p.53 8.2.5.2 b) 3)
			// iso10589 p.54 table 8
			switch pdu.CircuitType {
			case packet.CIRCUIT_TYPE_LEVEL1_ONLY:
				switch adjacency.adjUsage {
				case ADJ_USAGE_NONE:
					log.Debugf("Reject(Area mismatch)")
					action = P2P_IIH_ACTION_REJECT
				case ADJ_USAGE_LEVEL1:
					log.Debugf("Down(Area mismatch)")
					action = P2P_IIH_ACTION_DOWN
					adjacency.adjState = packet.ADJ_3WAY_STATE_DOWN
					circuit.removeAdjacency(remoteLanAddress, adjType)
					circuit.isis.updateChSend(&UpdateChMsg{
						msgType:   UPDATE_CH_MSG_TYPE_ADJACENCY_DOWN,
						adjacency: adjacency,
					})
				case ADJ_USAGE_LEVEL1AND2, ADJ_USAGE_LEVEL2:
					log.Debugf("Down(Wrong system)")
					action = P2P_IIH_ACTION_DOWN
					adjacency.adjState = packet.ADJ_3WAY_STATE_DOWN
					circuit.removeAdjacency(remoteLanAddress, adjType)
					circuit.isis.updateChSend(&UpdateChMsg{
						msgType:   UPDATE_CH_MSG_TYPE_ADJACENCY_DOWN,
						adjacency: adjacency,
					})
				}
			case packet.CIRCUIT_TYPE_LEVEL2_ONLY:
				switch adjacency.adjUsage {
				case ADJ_USAGE_NONE:
					action = P2P_IIH_ACTION_UP
					adjacency.adjState = packet.ADJ_3WAY_STATE_UP
					adjacency.adjUsage = ADJ_USAGE_LEVEL2
					circuit.addAdjacency(adjacency)
					circuit.isis.updateChSend(&UpdateChMsg{
						msgType:   UPDATE_CH_MSG_TYPE_ADJACENCY_UP,
						adjacency: adjacency,
					})
				case ADJ_USAGE_LEVEL1, ADJ_USAGE_LEVEL1AND2:
					action = P2P_IIH_ACTION_DOWN
					log.Debugf("Down(Wrong system)")
					adjacency.adjState = packet.ADJ_3WAY_STATE_DOWN
					circuit.removeAdjacency(remoteLanAddress, adjType)
					circuit.isis.updateChSend(&UpdateChMsg{
						msgType:   UPDATE_CH_MSG_TYPE_ADJACENCY_DOWN,
						adjacency: adjacency,
					})
				case ADJ_USAGE_LEVEL2:
					action = P2P_IIH_ACTION_ACCEPT
				}
			case packet.CIRCUIT_TYPE_BOTH_LEVEL1_AND_LEVEL2:
				switch adjacency.adjUsage {
				case ADJ_USAGE_NONE:
					action = P2P_IIH_ACTION_UP
					adjacency.adjState = packet.ADJ_3WAY_STATE_UP
					adjacency.adjUsage = ADJ_USAGE_LEVEL2
					circuit.addAdjacency(adjacency)
					circuit.isis.updateChSend(&UpdateChMsg{
						msgType:   UPDATE_CH_MSG_TYPE_ADJACENCY_UP,
						adjacency: adjacency,
					})
				case ADJ_USAGE_LEVEL1:
					log.Debugf("Down(Wrong system)")
					action = P2P_IIH_ACTION_DOWN
					adjacency.adjState = packet.ADJ_3WAY_STATE_DOWN
					circuit.removeAdjacency(remoteLanAddress, adjType)
					circuit.isis.updateChSend(&UpdateChMsg{
						msgType:   UPDATE_CH_MSG_TYPE_ADJACENCY_DOWN,
						adjacency: adjacency,
					})
				case ADJ_USAGE_LEVEL1AND2:
					log.Debugf("Down(Area mismatch)")
					action = P2P_IIH_ACTION_DOWN
					adjacency.adjState = packet.ADJ_3WAY_STATE_DOWN
					circuit.removeAdjacency(remoteLanAddress, adjType)
					circuit.isis.updateChSend(&UpdateChMsg{
						msgType:   UPDATE_CH_MSG_TYPE_ADJACENCY_DOWN,
						adjacency: adjacency,
					})
				case ADJ_USAGE_LEVEL2:
					action = P2P_IIH_ACTION_ACCEPT
				}
			}
		}
	}

	if action == P2P_IIH_ACTION_UP {
		sourceId := pdu.SourceId()
		// iso10589 p.53 8.2.5.2 c)
		if bytes.Compare(systemId[:], sourceId[:]) > 0 {
			// iso10589 p.53 8.2.5.2 c) 1)
			// XXX
		}
		if bytes.Compare(systemId[:], sourceId[:]) < 0 {
			// iso10589 p.53 8.2.5.2 c) 2)
			// XXX
		}
		if bytes.Compare(systemId[:], sourceId[:]) == 0 {
			// iso10589 p.53 8.2.5.2 c) 3)
			// XXX
		}
	}

	if action == P2P_IIH_ACTION_ACCEPT {
		// iso10589 p.53 8.2.5.2 d)
		if !bytes.Equal(systemId[:], adjacency.systemId[:]) {
			adjacency.adjState = packet.ADJ_3WAY_STATE_DOWN
			circuit.removeAdjacency(remoteLanAddress, adjType)
			circuit.isis.updateChSend(&UpdateChMsg{
				msgType:   UPDATE_CH_MSG_TYPE_ADJACENCY_DOWN,
				adjacency: adjacency,
			})
		}
	}

	if action == P2P_IIH_ACTION_UP || action == P2P_IIH_ACTION_ACCEPT {
		// iso10589 p.53 8.2.5.2 e)
		adjacency.areaAddresses = areaAddresses
		adjacency.holdingTime = pdu.HoldingTime
		adjacency.systemId = pdu.SourceId()
	}

}
