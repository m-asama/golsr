package server

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/m-asama/golsr/internal/pkg/isis/config"
	"github.com/m-asama/golsr/pkg/isis/packet"
)

type UpdateChMsgType uint8

const (
	_ UpdateChMsgType = iota
	UPDATE_CH_MSG_TYPE_CONFIG_CHANGED
	UPDATE_CH_MSG_TYPE_KERNEL_CHANGED
	UPDATE_CH_MSG_TYPE_ISIS_ENABLE
	UPDATE_CH_MSG_TYPE_ISIS_DISABLE
	UPDATE_CH_MSG_TYPE_CIRCUIT_ENABLE
	UPDATE_CH_MSG_TYPE_CIRCUIT_DISABLE
	UPDATE_CH_MSG_TYPE_CIRCUIT_UP
	UPDATE_CH_MSG_TYPE_CIRCUIT_DOWN
	UPDATE_CH_MSG_TYPE_CIRCUIT_CHANGED
	UPDATE_CH_MSG_TYPE_ADJACENCY_UP
	UPDATE_CH_MSG_TYPE_ADJACENCY_DOWN
	UPDATE_CH_MSG_TYPE_ADJACENCY_CHANGED
	UPDATE_CH_MSG_TYPE_LSP_CHANGED
	UPDATE_CH_MSG_TYPE_EXIT
)

func (msgType UpdateChMsgType) String() string {
	switch msgType {
	case UPDATE_CH_MSG_TYPE_CONFIG_CHANGED:
		return "UPDATE_CH_MSG_TYPE_CONFIG_CHANGED"
	case UPDATE_CH_MSG_TYPE_KERNEL_CHANGED:
		return "UPDATE_CH_MSG_TYPE_KERNEL_CHANGED"
	case UPDATE_CH_MSG_TYPE_ISIS_ENABLE:
		return "UPDATE_CH_MSG_TYPE_ISIS_ENABLE"
	case UPDATE_CH_MSG_TYPE_ISIS_DISABLE:
		return "UPDATE_CH_MSG_TYPE_ISIS_DISABLE"
	case UPDATE_CH_MSG_TYPE_CIRCUIT_ENABLE:
		return "UPDATE_CH_MSG_TYPE_CIRCUIT_ENABLE"
	case UPDATE_CH_MSG_TYPE_CIRCUIT_DISABLE:
		return "UPDATE_CH_MSG_TYPE_CIRCUIT_DISABLE"
	case UPDATE_CH_MSG_TYPE_CIRCUIT_UP:
		return "UPDATE_CH_MSG_TYPE_CIRCUIT_UP"
	case UPDATE_CH_MSG_TYPE_CIRCUIT_DOWN:
		return "UPDATE_CH_MSG_TYPE_CIRCUIT_DOWN"
	case UPDATE_CH_MSG_TYPE_CIRCUIT_CHANGED:
		return "UPDATE_CH_MSG_TYPE_CIRCUIT_CHANGED"
	case UPDATE_CH_MSG_TYPE_ADJACENCY_UP:
		return "UPDATE_CH_MSG_TYPE_ADJACENCY_UP"
	case UPDATE_CH_MSG_TYPE_ADJACENCY_DOWN:
		return "UPDATE_CH_MSG_TYPE_ADJACENCY_DOWN"
	case UPDATE_CH_MSG_TYPE_ADJACENCY_CHANGED:
		return "UPDATE_CH_MSG_TYPE_ADJACENCY_CHANGED"
	case UPDATE_CH_MSG_TYPE_EXIT:
		return "UPDATE_CH_MSG_TYPE_EXIT"
	case UPDATE_CH_MSG_TYPE_LSP_CHANGED:
		return "UPDATE_CH_MSG_TYPE_LSP_CHANGED"
	}
	log.Infof("")
	panic("")
	return fmt.Sprintf("UpdateChMsgType(%d)", msgType)
}

type UpdateChMsg struct {
	msgType   UpdateChMsgType
	circuit   *Circuit
	adjacency *Adjacency
}

func (msg *UpdateChMsg) String() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s", msg.msgType.String())
	if msg.circuit != nil {
		fmt.Fprintf(&b, " %s", msg.circuit.name)
	}
	if msg.adjacency != nil {
		fmt.Fprintf(&b, " %x", msg.adjacency.lanAddress)
	}
	return b.String()
}

func (isis *IsisServer) updateProcess(wg *sync.WaitGroup) {
	log.Debugf("enter")
	defer log.Debugf("exit")
	wg.Wait()
	for {
		circuitChanged := false
		lspChanged := false
		msg := <-isis.updateCh
		log.Debugf("%s", msg)
		switch msg.msgType {
		case UPDATE_CH_MSG_TYPE_CONFIG_CHANGED:
		case UPDATE_CH_MSG_TYPE_KERNEL_CHANGED:
		case UPDATE_CH_MSG_TYPE_ISIS_ENABLE:
		case UPDATE_CH_MSG_TYPE_ISIS_DISABLE:
		case UPDATE_CH_MSG_TYPE_CIRCUIT_ENABLE:
		case UPDATE_CH_MSG_TYPE_CIRCUIT_DISABLE:
		case UPDATE_CH_MSG_TYPE_CIRCUIT_UP:
			isis.circuitUp(msg.circuit)
		case UPDATE_CH_MSG_TYPE_CIRCUIT_DOWN:
			isis.circuitDown(msg.circuit)
		case UPDATE_CH_MSG_TYPE_CIRCUIT_CHANGED:
			circuitChanged = true
		case UPDATE_CH_MSG_TYPE_ADJACENCY_UP:
			isis.adjacencyUp(msg.adjacency)
		case UPDATE_CH_MSG_TYPE_ADJACENCY_DOWN:
			isis.adjacencyDown(msg.adjacency)
		case UPDATE_CH_MSG_TYPE_ADJACENCY_CHANGED:
		case UPDATE_CH_MSG_TYPE_LSP_CHANGED:
			lspChanged = true
		case UPDATE_CH_MSG_TYPE_EXIT:
			goto EXIT
		}
		if isis.changed() || circuitChanged || lspChanged {
			isis.updateOriginLsps()
			isis.decisionCh <- &DecisionChMsg{
				msgType: DECISION_CH_MSG_TYPE_DO,
			}
		}
	}
EXIT:
}

func (isis *IsisServer) circuitUp(circuit *Circuit) {
	log.Debug("enter: %s", circuit.name)
	defer log.Debug("exit: %s", circuit.name)
	now := time.Now()
	circuit.uptime = &now
	circuit.downtime = nil
	go func() {
		isis.updateCh <- &UpdateChMsg{
			msgType: UPDATE_CH_MSG_TYPE_CIRCUIT_CHANGED,
			circuit: circuit,
		}
	}()
}

func (isis *IsisServer) circuitDown(circuit *Circuit) {
	log.Debug("enter: %s", circuit.name)
	defer log.Debug("exit: %s", circuit.name)
	for _, adjacency := range circuit.adjacencyDb {
		adjacency.adjState = packet.ADJ_3WAY_STATE_DOWN
	}
	now := time.Now()
	circuit.uptime = nil
	circuit.downtime = &now
}

func (isis *IsisServer) adjacencyUp(adjacency *Adjacency) {
	log.Debug("enter: %x %s", adjacency.lanAddress, adjacency.adjType)
	defer log.Debug("exit: %x %s", adjacency.lanAddress, adjacency.adjType)
	if adjacency.adjType == ADJ_TYPE_P2P {
		// iso10589 p.42 7.3.17 a)
		isis.setSrmFlagForCircuit(adjacency.circuit)
		// iso10589 p.42 7.3.17 b)
		if adjacency.adjUsage == ADJ_USAGE_LEVEL1 || adjacency.adjUsage == ADJ_USAGE_LEVEL1AND2 {
			adjacency.circuit.sendCsn(packet.PDU_TYPE_LEVEL1_CSNP)
		}
		if adjacency.adjUsage == ADJ_USAGE_LEVEL2 || adjacency.adjUsage == ADJ_USAGE_LEVEL1AND2 {
			adjacency.circuit.sendCsn(packet.PDU_TYPE_LEVEL2_CSNP)
		}
	}
	if adjacency.adjType == ADJ_TYPE_LEVEL1_LAN {
	}
	if adjacency.adjType == ADJ_TYPE_LEVEL2_LAN {
	}
}

func (isis *IsisServer) adjacencyDown(adjacency *Adjacency) {
	log.Debug("enter: %x %s", adjacency.lanAddress, adjacency.adjType)
	defer log.Debug("exit: %x %s", adjacency.lanAddress, adjacency.adjType)
}

func (isis *IsisServer) changed() bool {
	log.Debug("enter")
	defer log.Debug("exit")

	changed := false

	newSystemId := config.ParseSystemId(*isis.config.Config.SystemId)
	if isis.systemIdChanged(newSystemId) {
		isis.systemId = newSystemId
		changed = true
	}

	newAreaAddresses := config.ParseAreaAddresses(isis.config.Config.AreaAddress)
	if isis.areaAddressesChanged(newAreaAddresses) {
		isis.areaAddresses = newAreaAddresses
		changed = true
	}

	for _, level := range ISIS_LEVEL_ALL {
		newIsReachabilities := isis.newIsReachabilities(level)
		if isis.isReachabilitiesChanged(level, newIsReachabilities) {
			isis.isReachabilities[level] = newIsReachabilities
			changed = true
		}

		newIpv4Reachabilities := isis.newIpv4Reachabilities(level)
		if isis.ipv4ReachabilitiesChanged(level, newIpv4Reachabilities) {
			isis.ipv4Reachabilities[level] = newIpv4Reachabilities
			changed = true
		}

		newIpv6Reachabilities := isis.newIpv6Reachabilities(level)
		if isis.ipv6ReachabilitiesChanged(level, newIpv6Reachabilities) {
			isis.ipv6Reachabilities[level] = newIpv6Reachabilities
			changed = true
		}
	}

	for _, circuit := range isis.circuitDb {
		if circuit.changed() {
			changed = true
		}
	}

	return changed
}

func (isis *IsisServer) systemIdChanged(newSystemId []byte) bool {
	log.Debug("enter")
	defer log.Debug("exit")
	if !bytes.Equal(isis.systemId, newSystemId) {
		return true
	}
	return false
}

func (isis *IsisServer) areaAddressesChanged(newAreaAddresses [][]byte) bool {
	log.Debug("enter")
	defer log.Debug("exit")
	if len(newAreaAddresses) != len(isis.areaAddresses) {
		return true
	}
	for i, _ := range isis.areaAddresses {
		if !bytes.Equal(newAreaAddresses[i], isis.areaAddresses[i]) {
			return true
		}
	}
	return false
}

func (isis *IsisServer) lspArrayAppend(lss *[]*packet.LsPdu, level IsisLevel, nodeId uint8) (int, error) {
	log.Debug("enter")
	defer log.Debug("exit")
	if len(*lss) == 256 {
		log.Infof("LSP array overflow")
		return -1, errors.New("LSP array overflow")
	}
	ls, err := packet.NewLsPdu(level.pduTypeLsp())
	if err != nil {
		log.Infof("LSP array append failed: %v", err)
		return -1, err
	}
	index := len(*lss)
	lspId := make([]byte, packet.LSP_ID_LENGTH)
	copy(lspId[0:packet.SYSTEM_ID_LENGTH], isis.systemId)
	lspId[packet.NEIGHBOUR_ID_LENGTH-1] = nodeId
	lspId[packet.LSP_ID_LENGTH-1] = uint8(index)
	ls.SetLspId(lspId)
	ls.IsType = level.isType()
	ls.RemainingLifetime = isis.lspLifetime()
	if nodeId == 0 {
		protocolsSupportedTlv, err := packet.NewProtocolsSupportedTlv()
		if err != nil {
			log.Infof("packet.NewProtocolsSupportedTlv failed: %v", err)
			return -1, err
		}
		if isis.ipv4Enable() {
			protocolsSupportedTlv.AddNlpId(packet.NLP_ID_IPV4)
		}
		if isis.ipv6Enable() {
			protocolsSupportedTlv.AddNlpId(packet.NLP_ID_IPV6)
		}
		ls.SetProtocolsSupportedTlv(protocolsSupportedTlv)
	}
	if nodeId == 0 {
		areaAddressesTlv, err := packet.NewAreaAddressesTlv()
		if err != nil {
			log.Infof("packet.NewAreaAddressesTlv failed: %v", err)
			return -1, err
		}
		for _, areaAddress := range isis.areaAddresses {
			areaAddressesTlv.AddAreaAddress(areaAddress)
		}
		ls.SetAreaAddressesTlv(areaAddressesTlv)
	}
	*lss = append(*lss, ls)
	return index, nil
}

func (isis *IsisServer) updateLocalSystemLsps() {
	log.Debug("enter")
	defer log.Debug("exit")
	for _, level := range ISIS_LEVEL_ALL {
		lss := make([]*packet.LsPdu, 0)
		index, err := isis.lspArrayAppend(&lss, level, uint8(0))
		if err != nil {
			log.Infof("lspArrayAppend failed: %v", err)
			return
		}
		if isis.old(level) {
			//
			isNeighboursLspTlv, err := packet.NewIsNeighboursLspTlv()
			if err != nil {
				log.Infof("packet.NewIsNeighboursLspTlv failed: %v", err)
				return
			}
			for _, ir := range isis.isReachabilities[level] {
				neigh, err := packet.NewIsNeighboursLspNeighbour(ir.neighborId)
				if err != nil {
					log.Infof("packet.NewIsNeighboursLspNeighbour failed: %v", err)
					return
				}
				neigh.DefaultMetric = uint8(ir.metric)
				err = isNeighboursLspTlv.AddNeighbour(neigh)
				if err != nil {
					log.Infof("AddNeighbour failed: %v", err)
					return
				}
			}
			err = lss[index].AddIsNeighboursLspTlv(isNeighboursLspTlv)
			if err != nil {
				log.Infof("AddIsNeighboursLspTlv failed: %v", err)
				return
			}
			//
			ipInternalReachInfoTlv, err := packet.NewIpInternalReachInfoTlv()
			if err != nil {
				log.Infof("packet.NewIpInternalReachInfoTlv failed: %v", err)
				return
			}
			for _, ir := range isis.ipv4Reachabilities[level] {
				if ir.scopeHost {
					continue
				}
				subnet, err := packet.NewIpInternalReachInfoIpSubnet()
				subnet.DefaultMetric = uint8(ir.metric)
				subnet.IpAddress = ir.ipv4Prefix
				subnet.SubnetMask = plen2snmask4(ir.prefixLength)
				err = ipInternalReachInfoTlv.AddIpSubnet(subnet)
				if err != nil {
					log.Infof("AddIpSubnet failed: %v", err)
					return
				}
			}
			err = lss[index].AddIpInternalReachInfoTlv(ipInternalReachInfoTlv)
			if err != nil {
				log.Infof("AddIpInternalReachInfoTlv failed: %v", err)
				return
			}
		}
		if isis.wide(level) {
			//
			extendedIsReachabilityTlv, err := packet.NewExtendedIsReachabilityTlv()
			if err != nil {
				log.Infof("packet.NewExtendedIsReachabilityTlv failed: %v", err)
				return
			}
			for _, ir := range isis.isReachabilities[level] {
				neigh, err := packet.NewExtendedIsReachabilityNeighbour(ir.neighborId)
				if err != nil {
					log.Infof("packet.NewExtendedIsReachabilityNeighbour failed: %v", err)
					return
				}
				neigh.DefaultMetric = ir.metric
				err = extendedIsReachabilityTlv.AddNeighbour(neigh)
				if err != nil {
					log.Infof("AddNeighbour failed: %v", err)
					return
				}
			}
			err = lss[index].AddExtendedIsReachabilityTlv(extendedIsReachabilityTlv)
			if err != nil {
				log.Infof("AddExtendedIsReachabilityTlv failed: %v", err)
				return
			}
			//
			extendedIpReachabilityTlv, err := packet.NewExtendedIpReachabilityTlv()
			if err != nil {
				log.Infof("packet.NewExtendedIpReachabilityTlv failed: %v", err)
				return
			}
			for _, ir := range isis.ipv4Reachabilities[level] {
				if ir.scopeHost {
					continue
				}
				subnet, err := packet.NewExtendedIpReachabilityIpv4Prefix(
					ir.ipv4Prefix, ir.prefixLength)
				subnet.MetricInformation = ir.metric
				err = extendedIpReachabilityTlv.AddIpv4Prefix(subnet)
				if err != nil {
					log.Infof("AddIpv4Prefix failed: %v", err)
					return
				}
			}
			err = lss[index].AddExtendedIpReachabilityTlv(extendedIpReachabilityTlv)
			if err != nil {
				log.Infof("AddExtendedIpReachabilityTlv failed: %v", err)
				return
			}
		}
		//
		ipv6ReachabilityTlv, err := packet.NewIpv6ReachabilityTlv()
		if err != nil {
			log.Infof("packet.NewIpv6ReachabilityTlv failed: %v", err)
			return
		}
		for _, ir := range isis.ipv6Reachabilities[level] {
			if ir.scopeLink || ir.scopeHost {
				continue
			}
			subnet, err := packet.NewIpv6ReachabilityIpv6Prefix(
				ir.ipv6Prefix, ir.prefixLength)
			subnet.Metric = ir.metric
			err = ipv6ReachabilityTlv.AddIpv6Prefix(subnet)
			if err != nil {
				log.Infof("AddIpv6Prefix failed: %v", err)
				return
			}
		}
		err = lss[index].AddIpv6ReachabilityTlv(ipv6ReachabilityTlv)
		if err != nil {
			log.Infof("AddIpv6ReachabilityTlv failed: %v", err)
			return
		}
		//
		cur := isis.originLss(level, 0)
		check := make(map[*Ls]bool)
		for _, p := range cur {
			check[p] = true
		}
		for _, ls := range lss {
			found := false
			for _, curtmp := range cur {
				if bytes.Equal(ls.LspId(), curtmp.pdu.LspId()) {
					found = true
					ls.SequenceNumber = curtmp.pdu.SequenceNumber + 1
					ls.SetChecksum()
					curtmp.pdu = ls
					isis.setSrmFlagAll(curtmp)
					delete(check, curtmp)
				}
			}
			if !found {
				now := time.Now()
				ls.SequenceNumber = 1
				ls.SetChecksum()
				p := isis.insertLsp(ls, true, &now)
				isis.setSrmFlagAll(p)
			}
		}
		for p, _ := range check {
			p.pdu.RemainingLifetime = 0
			isis.setSrmFlagAll(p)
		}
	}
}

func (isis *IsisServer) updatePseudoNodeLsps(circuit *Circuit, level IsisLevel) {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)
	for _, level := range ISIS_LEVEL_ALL {
		lss := make([]*packet.LsPdu, 0)
		index, err := isis.lspArrayAppend(&lss, level, circuit.localCircuitId)
		if err != nil {
			log.Infof("lspArrayAppend failed: %v", err)
			return
		}
		if isis.old(level) {
			isNeighboursLspTlv, err := packet.NewIsNeighboursLspTlv()
			if err != nil {
				log.Infof("packet.NewIsNeighboursLspTlv failed: %v", err)
				return
			}
			neighborId := make([]byte, packet.NEIGHBOUR_ID_LENGTH)
			copy(neighborId, isis.systemId)
			neigh, err := packet.NewIsNeighboursLspNeighbour(neighborId)
			if err != nil {
				log.Infof("packet.NewIsNeighboursLspNeighbour failed: %v", err)
				return
			}
			neigh.DefaultMetric = uint8(0)
			err = isNeighboursLspTlv.AddNeighbour(neigh)
			if err != nil {
				log.Infof("AddNeighbour failed: %v", err)
				return
			}
			//for _, ir := range isis.isReachabilities[level] {
			for _, adj := range circuit.adjacencyDb {
				if !adj.level(level) || adj.adjState != packet.ADJ_3WAY_STATE_UP {
					continue
				}
				neighborId := make([]byte, packet.NEIGHBOUR_ID_LENGTH)
				copy(neighborId, adj.systemId)
				neigh, err := packet.NewIsNeighboursLspNeighbour(neighborId)
				if err != nil {
					log.Infof("packet.NewIsNeighboursLspNeighbour failed: %v", err)
					return
				}
				neigh.DefaultMetric = uint8(0)
				err = isNeighboursLspTlv.AddNeighbour(neigh)
				if err != nil {
					log.Infof("AddNeighbour failed: %v", err)
					return
				}
			}
			err = lss[index].AddIsNeighboursLspTlv(isNeighboursLspTlv)
			if err != nil {
				log.Infof("AddIsNeighboursLspTlv failed: %v", err)
				return
			}
		}
		if isis.wide(level) {
			extendedIsReachabilityTlv, err := packet.NewExtendedIsReachabilityTlv()
			if err != nil {
				log.Infof("packet.NewExtendedIsReachabilityTlv failed: %v", err)
				return
			}
			neighborId := make([]byte, packet.NEIGHBOUR_ID_LENGTH)
			copy(neighborId, isis.systemId)
			neigh, err := packet.NewExtendedIsReachabilityNeighbour(neighborId)
			if err != nil {
				log.Infof("packet.NewExtendedIsReachabilityNeighbour failed: %v", err)
				return
			}
			neigh.DefaultMetric = 0
			err = extendedIsReachabilityTlv.AddNeighbour(neigh)
			if err != nil {
				log.Infof("AddNeighbour failed: %v", err)
				return
			}
			//for _, ir := range isis.isReachabilities[level] {
			for _, adj := range circuit.adjacencyDb {
				if !adj.level(level) || adj.adjState != packet.ADJ_3WAY_STATE_UP {
					continue
				}
				neighborId := make([]byte, packet.NEIGHBOUR_ID_LENGTH)
				copy(neighborId, adj.systemId)
				neigh, err := packet.NewExtendedIsReachabilityNeighbour(neighborId)
				if err != nil {
					log.Infof("packet.NewExtendedIsReachabilityNeighbour failed: %v", err)
					return
				}
				neigh.DefaultMetric = 0
				err = extendedIsReachabilityTlv.AddNeighbour(neigh)
				if err != nil {
					log.Infof("AddNeighbour failed: %v", err)
					return
				}
			}
			err = lss[index].AddExtendedIsReachabilityTlv(extendedIsReachabilityTlv)
			if err != nil {
				log.Infof("AddExtendedIsReachabilityTlv failed: %v", err)
				return
			}
		}
		cur := isis.originLss(level, circuit.localCircuitId)
		check := make(map[*Ls]bool)
		for _, p := range cur {
			check[p] = true
		}
		for _, ls := range lss {
			found := false
			for _, curtmp := range cur {
				if bytes.Equal(ls.LspId(), curtmp.pdu.LspId()) {
					found = true
					ls.SequenceNumber = curtmp.pdu.SequenceNumber + 1
					ls.SetChecksum()
					curtmp.pdu = ls
					isis.setSrmFlagAll(curtmp)
					delete(check, curtmp)
				}
			}
			if !found {
				now := time.Now()
				ls.SequenceNumber = 1
				ls.SetChecksum()
				p := isis.insertLsp(ls, true, &now)
				isis.setSrmFlagAll(p)
			}
		}
		for p, _ := range check {
			p.pdu.RemainingLifetime = 0
			isis.setSrmFlagAll(p)
		}
	}
}

func (isis *IsisServer) updateOriginLsps() {
	log.Debugf("enter")
	defer log.Debugf("exit")
	//now := time.Now()
	isis.updateLocalSystemLsps()
	for _, circuit := range isis.circuitDb {
		for _, level := range ISIS_LEVEL_ALL {
			/*
				d := time.Second * circuit.sendLanIihInterval(level) * 2
				d -= time.Millisecond * 10
				if circuit.uptime == nil || !circuit.uptime.Add(d).Before(now) {
					continue
				}
			*/
			if circuit.designated(level) {
				isis.updatePseudoNodeLsps(circuit, level)
			}
		}
	}
	go isis.scheduleHandleFlags()
}
