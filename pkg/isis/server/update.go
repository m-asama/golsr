package server

import (
	"bytes"
	"fmt"

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
	}
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

func (isis *IsisServer) updateProcess() {
	log.Debugf("")
	for {
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
		case UPDATE_CH_MSG_TYPE_CIRCUIT_CHANGED:
		case UPDATE_CH_MSG_TYPE_ADJACENCY_UP:
			isis.adjacencyUp(msg.adjacency)
		case UPDATE_CH_MSG_TYPE_ADJACENCY_DOWN:
		case UPDATE_CH_MSG_TYPE_ADJACENCY_CHANGED:
		case UPDATE_CH_MSG_TYPE_EXIT:
			goto EXIT
		}
		if isis.changed() {
			isis.generateLsps()
			isis.decisionCh <- &DecisionChMsg{
				msgType: DECISION_CH_MSG_TYPE_DO,
			}
		}
	}
EXIT:
}

func (isis *IsisServer) circuitUp(circuit *Circuit) {
}

func (isis *IsisServer) adjacencyUp(adjacency *Adjacency) {
	if adjacency.adjType == ADJ_TYPE_P2P {
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

func (isis *IsisServer) changed() bool {
	log.Debug("")

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

	newLevel1IsReachabilities := isis.newIsReachabilities(ISIS_LEVEL_1)
	if isis.isReachabilitiesChanged(ISIS_LEVEL_1, newLevel1IsReachabilities) {
		isis.level1IsReachabilities = newLevel1IsReachabilities
		changed = true
	}

	newLevel2IsReachabilities := isis.newIsReachabilities(ISIS_LEVEL_2)
	if isis.isReachabilitiesChanged(ISIS_LEVEL_2, newLevel2IsReachabilities) {
		isis.level2IsReachabilities = newLevel2IsReachabilities
		changed = true
	}

	newLevel1Ipv4Reachabilities := isis.newIpv4Reachabilities(ISIS_LEVEL_1)
	if isis.ipv4ReachabilitiesChanged(ISIS_LEVEL_1, newLevel1Ipv4Reachabilities) {
		isis.level1Ipv4Reachabilities = newLevel1Ipv4Reachabilities
		changed = true
	}

	newLevel2Ipv4Reachabilities := isis.newIpv4Reachabilities(ISIS_LEVEL_2)
	if isis.ipv4ReachabilitiesChanged(ISIS_LEVEL_2, newLevel2Ipv4Reachabilities) {
		isis.level2Ipv4Reachabilities = newLevel2Ipv4Reachabilities
		changed = true
	}

	newLevel1Ipv6Reachabilities := isis.newIpv6Reachabilities(ISIS_LEVEL_1)
	if isis.ipv6ReachabilitiesChanged(ISIS_LEVEL_1, newLevel1Ipv6Reachabilities) {
		isis.level1Ipv6Reachabilities = newLevel1Ipv6Reachabilities
		changed = true
	}

	newLevel2Ipv6Reachabilities := isis.newIpv6Reachabilities(ISIS_LEVEL_2)
	if isis.ipv6ReachabilitiesChanged(ISIS_LEVEL_2, newLevel2Ipv6Reachabilities) {
		isis.level2Ipv6Reachabilities = newLevel2Ipv6Reachabilities
		changed = true
	}

	for _, circuit := range isis.circuitDb {
		if circuit.changed() {
			changed = true
		}
	}

	return changed
}

func (isis *IsisServer) systemIdChanged(newSystemId []byte) bool {
	if !bytes.Equal(isis.systemId, newSystemId) {
		return true
	}
	return false
}

func (isis *IsisServer) areaAddressesChanged(newAreaAddresses [][]byte) bool {
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

// XXX: fix sort algo
func (isis *IsisServer) sortIsReachabilities(isReachabilities []*IsReachability) {
	for i := 0; i < len(isReachabilities); i++ {
		for j := 0; j < len(isReachabilities); j++ {
			if i == j {
				continue
			}
			if bytes.Compare(isReachabilities[i].neighborId, isReachabilities[j].neighborId) > 0 {
				tmp := isReachabilities[i]
				isReachabilities[i] = isReachabilities[j]
				isReachabilities[j] = tmp
			}
		}
	}
}

func (isis *IsisServer) currentIsReachabilities(level IsisLevel) []*IsReachability {
	var current []*IsReachability
	switch level {
	case ISIS_LEVEL_1:
		current = isis.level1IsReachabilities
	case ISIS_LEVEL_2:
		current = isis.level2IsReachabilities
	}
	return current
}

func (isis *IsisServer) newIsReachabilities(level IsisLevel) []*IsReachability {
	new := make([]*IsReachability, 0)
	for _, circuit := range isis.circuitDb {
		for _, adjacency := range circuit.adjacencyDb {
			if adjacency.adjState != packet.ADJ_3WAY_STATE_UP {
				continue
			}
			neighborId := make([]byte, len(adjacency.systemId))
			copy(neighborId, adjacency.systemId)
			isr := &IsReachability{
				neighborId: neighborId,
				metric:     adjacency.circuit.metric(level),
				lspNumber:  -1,
			}
			new = append(new, isr)
		}
	}
	for _, ctmp := range isis.currentIsReachabilities(level) {
		for _, ntmp := range new {
			if bytes.Equal(ntmp.neighborId, ctmp.neighborId) {
				ntmp.lspNumber = ctmp.lspNumber
			}
		}
	}
	isis.sortIsReachabilities(new)
	return new
}

func (isis *IsisServer) isReachabilitiesChanged(level IsisLevel, new []*IsReachability) bool {
	current := isis.currentIsReachabilities(level)
	if len(current) != len(new) {
		return true
	}
	for i := 0; i < len(current); i++ {
		if !bytes.Equal(current[i].neighborId, new[i].neighborId) ||
			current[i].metric != new[i].metric {
			return true
		}
	}
	return false
}

// XXX: fix sort algo
func (isis *IsisServer) sortIpv4Reachabilities(ipv4Reachabilities []*Ipv4Reachability) {
	for i := 0; i < len(ipv4Reachabilities); i++ {
		for j := 0; j < len(ipv4Reachabilities); j++ {
			if i == j {
				continue
			}
			if ipv4Reachabilities[i].ipv4Prefix > ipv4Reachabilities[j].ipv4Prefix {
				tmp := ipv4Reachabilities[i]
				ipv4Reachabilities[i] = ipv4Reachabilities[j]
				ipv4Reachabilities[j] = tmp
			}
			if ipv4Reachabilities[i].ipv4Prefix != ipv4Reachabilities[j].ipv4Prefix {
				continue
			}
			if ipv4Reachabilities[i].prefixLength > ipv4Reachabilities[j].prefixLength {
				tmp := ipv4Reachabilities[i]
				ipv4Reachabilities[i] = ipv4Reachabilities[j]
				ipv4Reachabilities[j] = tmp
			}
		}
	}
}

func (isis *IsisServer) currentIpv4Reachabilities(level IsisLevel) []*Ipv4Reachability {
	var current []*Ipv4Reachability
	switch level {
	case ISIS_LEVEL_1:
		current = isis.level1Ipv4Reachabilities
	case ISIS_LEVEL_2:
		current = isis.level2Ipv4Reachabilities
	}
	return current
}

func (isis *IsisServer) newIpv4Reachabilities(level IsisLevel) []*Ipv4Reachability {
	new := make([]*Ipv4Reachability, 0)
	for _, iface := range isis.kernel.Interfaces {
		circuit, ok := isis.circuitDb[iface.IfIndex]
		if !ok {
			continue
		}
		for _, ipv4Address := range iface.Ipv4Addresses {
			ipv4r := &Ipv4Reachability{
				ipv4Prefix:   ipv4Address.Address,
				prefixLength: uint8(ipv4Address.PrefixLength),
				metric:       circuit.metric(level),
				lspNumber:    -1,
			}
			new = append(new, ipv4r)
		}
	}
	for _, ctmp := range isis.currentIpv4Reachabilities(level) {
		for _, ntmp := range new {
			if ntmp.ipv4Prefix == ctmp.ipv4Prefix &&
				ntmp.prefixLength == ctmp.prefixLength {
				ntmp.lspNumber = ctmp.lspNumber
			}
		}
	}
	isis.sortIpv4Reachabilities(new)
	return new
}

func (isis *IsisServer) ipv4ReachabilitiesChanged(level IsisLevel, new []*Ipv4Reachability) bool {
	current := isis.currentIpv4Reachabilities(level)
	if len(current) != len(new) {
		return true
	}
	for i := 0; i < len(current); i++ {
		if current[i].ipv4Prefix != new[i].ipv4Prefix ||
			current[i].prefixLength != new[i].prefixLength ||
			current[i].metric != new[i].metric {
			return true
		}
	}
	return false
}

// XXX: fix sort algo
func (isis *IsisServer) sortIpv6Reachabilities(ipv6Reachabilities []*Ipv6Reachability) {
	for i := 0; i < len(ipv6Reachabilities); i++ {
		for j := 0; j < len(ipv6Reachabilities); j++ {
			if i == j {
				continue
			}
			if ipv6Reachabilities[i].ipv6Prefix[0] > ipv6Reachabilities[j].ipv6Prefix[0] {
				tmp := ipv6Reachabilities[i]
				ipv6Reachabilities[i] = ipv6Reachabilities[j]
				ipv6Reachabilities[j] = tmp
			}
			if ipv6Reachabilities[i].ipv6Prefix[0] != ipv6Reachabilities[j].ipv6Prefix[0] {
				continue
			}
			if ipv6Reachabilities[i].ipv6Prefix[1] > ipv6Reachabilities[j].ipv6Prefix[1] {
				tmp := ipv6Reachabilities[i]
				ipv6Reachabilities[i] = ipv6Reachabilities[j]
				ipv6Reachabilities[j] = tmp
			}
			if ipv6Reachabilities[i].ipv6Prefix[1] != ipv6Reachabilities[j].ipv6Prefix[1] {
				continue
			}
			if ipv6Reachabilities[i].ipv6Prefix[2] > ipv6Reachabilities[j].ipv6Prefix[2] {
				tmp := ipv6Reachabilities[i]
				ipv6Reachabilities[i] = ipv6Reachabilities[j]
				ipv6Reachabilities[j] = tmp
			}
			if ipv6Reachabilities[i].ipv6Prefix[2] != ipv6Reachabilities[j].ipv6Prefix[2] {
				continue
			}
			if ipv6Reachabilities[i].ipv6Prefix[3] > ipv6Reachabilities[j].ipv6Prefix[3] {
				tmp := ipv6Reachabilities[i]
				ipv6Reachabilities[i] = ipv6Reachabilities[j]
				ipv6Reachabilities[j] = tmp
			}
			if ipv6Reachabilities[i].ipv6Prefix[3] != ipv6Reachabilities[j].ipv6Prefix[3] {
				continue
			}
			if ipv6Reachabilities[i].prefixLength > ipv6Reachabilities[j].prefixLength {
				tmp := ipv6Reachabilities[i]
				ipv6Reachabilities[i] = ipv6Reachabilities[j]
				ipv6Reachabilities[j] = tmp
			}
		}
	}
}

func (isis *IsisServer) currentIpv6Reachabilities(level IsisLevel) []*Ipv6Reachability {
	var current []*Ipv6Reachability
	switch level {
	case ISIS_LEVEL_1:
		current = isis.level1Ipv6Reachabilities
	case ISIS_LEVEL_2:
		current = isis.level2Ipv6Reachabilities
	}
	return current
}

func (isis *IsisServer) newIpv6Reachabilities(level IsisLevel) []*Ipv6Reachability {
	new := make([]*Ipv6Reachability, 0)
	for _, iface := range isis.kernel.Interfaces {
		circuit, ok := isis.circuitDb[iface.IfIndex]
		if !ok {
			continue
		}
		for _, ipv6Address := range iface.Ipv6Addresses {
			ipv6r := &Ipv6Reachability{
				ipv6Prefix: [4]uint32{
					ipv6Address.Address[0],
					ipv6Address.Address[1],
					ipv6Address.Address[2],
					ipv6Address.Address[3],
				},
				prefixLength: uint8(ipv6Address.PrefixLength),
				metric:       circuit.metric(level),
				lspNumber:    -1,
			}
			new = append(new, ipv6r)
		}
	}
	for _, ctmp := range isis.currentIpv6Reachabilities(level) {
		for _, ntmp := range new {
			if ntmp.ipv6Prefix[0] == ctmp.ipv6Prefix[0] &&
				ntmp.ipv6Prefix[1] == ctmp.ipv6Prefix[1] &&
				ntmp.ipv6Prefix[2] == ctmp.ipv6Prefix[2] &&
				ntmp.ipv6Prefix[3] == ctmp.ipv6Prefix[3] &&
				ntmp.prefixLength == ctmp.prefixLength {
				ntmp.lspNumber = ctmp.lspNumber
			}
		}
	}
	isis.sortIpv6Reachabilities(new)
	return new
}

func (isis *IsisServer) ipv6ReachabilitiesChanged(level IsisLevel, new []*Ipv6Reachability) bool {
	current := isis.currentIpv6Reachabilities(level)
	if len(current) != len(new) {
		return true
	}
	for i := 0; i < len(current); i++ {
		if current[i].ipv6Prefix[0] != new[i].ipv6Prefix[0] ||
			current[i].ipv6Prefix[1] != new[i].ipv6Prefix[1] ||
			current[i].ipv6Prefix[2] != new[i].ipv6Prefix[2] ||
			current[i].ipv6Prefix[3] != new[i].ipv6Prefix[3] ||
			current[i].prefixLength != new[i].prefixLength ||
			current[i].metric != new[i].metric {
			return true
		}
	}
	return false
}

func (isis *IsisServer) generateSystemLsps() {
	log.Debugf("")
	//systemLsps := make(map[int]*Ls)
	//for _, _ := range isis.level1IsReachabilities
}

func (isis *IsisServer) generatePseudoNodeLsps(circuit *Circuit, level IsisLevel) {
	log.Debugf("%s", circuit.name)
}

func (isis *IsisServer) generateLsps() {
	log.Debugf("")
	isis.generateSystemLsps()
	for _, circuit := range isis.circuitDb {
		if circuit.designated(ISIS_LEVEL_1) {
			isis.generatePseudoNodeLsps(circuit, ISIS_LEVEL_1)
		}
		if circuit.designated(ISIS_LEVEL_2) {
			isis.generatePseudoNodeLsps(circuit, ISIS_LEVEL_2)
		}
	}
}
