package server

import (
	"bytes"
	"errors"
	"math"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/m-asama/golsr/internal/pkg/isis/config"
	"github.com/m-asama/golsr/internal/pkg/kernel"
	"github.com/m-asama/golsr/pkg/isis/packet"
)

type CircuitChMsg uint8

const (
	_ CircuitChMsg = iota
	CIRCUIT_CH_MSG_START
	CIRCUIT_CH_MSG_STOP
	CIRCUIT_CH_MSG_EXIT
)

type CircuitChState uint8

const (
	_ CircuitChState = iota
	CIRCUIT_CH_STATE_RUNNING
	CIRCUIT_CH_STATE_SUSPENDED
)

type Circuit struct {
	isis     *IsisServer
	ifKernel *kernel.Interface
	ifConfig *config.Interface

	name                   string
	fd                     int
	localCircuitId         uint8
	extendedLocalCircuitId uint32
	isReachabilities       [ISIS_LEVEL_NUM][]*IsReachability
	//previousIsReachabilities [ISIS_LEVEL_NUM][]*IsReachability
	uptime   *time.Time
	downtime *time.Time

	adjacencyDb []*Adjacency

	snSenderCh        chan *packet.SnPdu
	lsSenderCh        chan *packet.LsPdu
	p2pIihSenderCh    chan CircuitChMsg
	p2pIihSenderState CircuitChState
	l1lIihSenderCh    chan CircuitChMsg
	l1lIihSenderState CircuitChState
	l2lIihSenderCh    chan CircuitChMsg
	l2lIihSenderState CircuitChState
	l1lCsnSenderCh    chan CircuitChMsg
	l1lCsnSenderState CircuitChState
	l2lCsnSenderCh    chan CircuitChMsg
	l2lCsnSenderState CircuitChState
	receiverCh        chan CircuitChMsg
	receiverState     CircuitChState
}

func newLocalCircuitId(isis *IsisServer) (uint8, error) {
	log.Debugf("enter")
	defer log.Debugf("exit")
	localCircuitId := 0
	for _, ctmp := range isis.circuitDb {
		if int(ctmp.localCircuitId) > localCircuitId {
			localCircuitId = int(ctmp.localCircuitId)
		}
	}
	localCircuitId++
	if localCircuitId < 256 {
		return uint8(localCircuitId), nil
	}
	for localCircuitId := 1; localCircuitId < 256; localCircuitId++ {
		found := false
		for _, ctmp := range isis.circuitDb {
			if int(ctmp.localCircuitId) == localCircuitId {
				found = true
			}
		}
		if !found {
			return uint8(localCircuitId), nil
		}
	}
	return 0, errors.New("new local circuit id allocation failed")
}

func NewCircuit(isis *IsisServer, ifKernel *kernel.Interface, ifConfig *config.Interface) *Circuit {
	log.Debugf("enter")
	defer log.Debugf("exit")
	if isis == nil || ifKernel == nil || ifConfig == nil {
		log.Info("nil arg error")
		return nil
	}
	now := time.Now()
	var uptime, downtime *time.Time
	localCircuitId, err := newLocalCircuitId(isis)
	extendedLocalCircuitId := uint32(localCircuitId)
	if err != nil {
		log.Infof("%v", err)
		return nil
	}
	if ifKernel.Up {
		uptime = &now
	} else {
		downtime = &now
	}
	circuit := &Circuit{
		isis:                   isis,
		ifKernel:               ifKernel,
		ifConfig:               ifConfig,
		name:                   ifKernel.Name,
		fd:                     -1,
		localCircuitId:         localCircuitId,
		extendedLocalCircuitId: extendedLocalCircuitId,
		uptime:                 uptime,
		downtime:               downtime,
		adjacencyDb:            make([]*Adjacency, 0),
		snSenderCh:             make(chan *packet.SnPdu, 8),
		lsSenderCh:             make(chan *packet.LsPdu, 8),
		p2pIihSenderCh:         make(chan CircuitChMsg),
		p2pIihSenderState:      CIRCUIT_CH_STATE_SUSPENDED,
		l1lIihSenderCh:         make(chan CircuitChMsg),
		l1lIihSenderState:      CIRCUIT_CH_STATE_SUSPENDED,
		l2lIihSenderCh:         make(chan CircuitChMsg),
		l2lIihSenderState:      CIRCUIT_CH_STATE_SUSPENDED,
		l1lCsnSenderCh:         make(chan CircuitChMsg),
		l1lCsnSenderState:      CIRCUIT_CH_STATE_SUSPENDED,
		l2lCsnSenderCh:         make(chan CircuitChMsg),
		l2lCsnSenderState:      CIRCUIT_CH_STATE_SUSPENDED,
		receiverCh:             make(chan CircuitChMsg),
		receiverState:          CIRCUIT_CH_STATE_SUSPENDED,
	}
	for _, level := range ISIS_LEVEL_ALL {
		circuit.isReachabilities[level] = make([]*IsReachability, 0)
		//circuit.previousIsReachabilities[level] = make([]*IsReachability, 0)
	}
	if ifKernel.Up {
		go func() {
			isis.updateCh <- &UpdateChMsg{
				msgType: UPDATE_CH_MSG_TYPE_CIRCUIT_CHANGED,
				circuit: circuit,
			}
		}()
	}
	return circuit
}

func (circuit *Circuit) Serve() {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)
	go circuit.snSender()
	go circuit.lsSender()
	go circuit.p2pIihSender()
	go circuit.l1lIihSender()
	go circuit.l2lIihSender()
	go circuit.l1lCsnSender()
	go circuit.l2lCsnSender()
	go circuit.receiver()
}

func (circuit *Circuit) Exit() {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)
	close(circuit.snSenderCh)
	close(circuit.lsSenderCh)
	circuit.p2pIihSenderCh <- CIRCUIT_CH_MSG_EXIT
	circuit.l1lIihSenderCh <- CIRCUIT_CH_MSG_EXIT
	circuit.l2lIihSenderCh <- CIRCUIT_CH_MSG_EXIT
	circuit.l1lCsnSenderCh <- CIRCUIT_CH_MSG_EXIT
	circuit.l2lCsnSenderCh <- CIRCUIT_CH_MSG_EXIT
	circuit.receiverCh <- CIRCUIT_CH_MSG_EXIT
}

func (circuit *Circuit) SetEnable() {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)
	*circuit.ifConfig.Config.Enable = true
}

func (circuit *Circuit) SetDisable() {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)
	*circuit.ifConfig.Config.Enable = false
}

func (circuit *Circuit) SetPassive() {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)
	*circuit.ifConfig.Config.Passive = true
}

func (circuit *Circuit) SetActive() {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)
	*circuit.ifConfig.Config.Passive = false
}

func (circuit *Circuit) enable() bool {
	return *circuit.ifConfig.Config.Enable
}

func (circuit *Circuit) passive() bool {
	return *circuit.ifConfig.Config.Passive
}

func (circuit *Circuit) ready() bool {
	return circuit.isis.ready() && circuit.enable() && !circuit.passive()
}

func (circuit *Circuit) level1() bool {
	return *circuit.ifConfig.Config.LevelType == "level-all" ||
		*circuit.ifConfig.Config.LevelType == "level-1"
}

func (circuit *Circuit) level1Only() bool {
	return *circuit.ifConfig.Config.LevelType == "level-1"
}

func (circuit *Circuit) level2() bool {
	return *circuit.ifConfig.Config.LevelType == "level-all" ||
		*circuit.ifConfig.Config.LevelType == "level-2"
}

func (circuit *Circuit) level2Only() bool {
	return *circuit.ifConfig.Config.LevelType == "level-2"
}

func (circuit *Circuit) levelAll() bool {
	return *circuit.ifConfig.Config.LevelType == "level-all"
}

func (circuit *Circuit) lspPacingInterval() uint32 {
	return *circuit.ifConfig.Config.LspPacingInterval
}

func (circuit *Circuit) lspRetransmitInterval() uint16 {
	return *circuit.ifConfig.Config.LspRetransmitInterval
}

func (circuit *Circuit) designated(level IsisLevel) bool {
	if !circuit.ready() {
		//log.Debugf("%s: !circuit.ready()", level)
		return false
	}
	if !circuit.configBcast() {
		//log.Debugf("%s: !circuit.configBcast()", level)
		return false
	}
	for _, adjacency := range circuit.adjacencyDb {
		//log.Debugf("%s: %x %s", level, adjacency.lanId, adjacency.adjState)
		if adjacency.adjState != packet.ADJ_3WAY_STATE_UP ||
			level == ISIS_LEVEL_1 && adjacency.adjType != ADJ_TYPE_LEVEL1_LAN ||
			level == ISIS_LEVEL_2 && adjacency.adjType != ADJ_TYPE_LEVEL2_LAN {
			//log.Debugf("%s: continue", level)
			continue
		}
		if circuit.priority(level) < adjacency.priority ||
			circuit.priority(level) == adjacency.priority &&
				bytes.Compare(circuit.kernelHardwareAddr(), adjacency.lanAddress) < 0 {
			//log.Debugf("%s: false", level)
			return false
		}
	}
	//log.Debugf("%s: true", level)
	return true
}

func (circuit *Circuit) lanId(level IsisLevel) []byte {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)
	lanId := make([]byte, packet.NEIGHBOUR_ID_LENGTH)
	copy(lanId[0:packet.SYSTEM_ID_LENGTH], circuit.isis.systemId)
	lanId[packet.NEIGHBOUR_ID_LENGTH-1] = circuit.localCircuitId
	if circuit.designated(level) {
		return lanId
	}
	var designated *Adjacency
	for _, adjacency := range circuit.adjacencyDb {
		if adjacency.adjState != packet.ADJ_3WAY_STATE_UP ||
			level == ISIS_LEVEL_1 && adjacency.adjType != ADJ_TYPE_LEVEL1_LAN ||
			level == ISIS_LEVEL_2 && adjacency.adjType != ADJ_TYPE_LEVEL2_LAN {
			continue
		}
		if designated == nil {
			designated = adjacency
			continue
		}
		if designated.priority < adjacency.priority ||
			designated.priority == adjacency.priority &&
				bytes.Compare(designated.lanAddress, adjacency.lanAddress) < 0 {
			designated = adjacency
		}
	}
	if designated != nil {
		//copy(lanId, designated.lanId)
		copy(lanId[0:packet.SYSTEM_ID_LENGTH], designated.systemId)
		lanId[packet.NEIGHBOUR_ID_LENGTH-1] = designated.circuitId
	}
	return lanId
}

func (circuit *Circuit) helloInterval(level IsisLevel) uint16 {
	switch level {
	case ISIS_LEVEL_1:
		return *circuit.ifConfig.HelloInterval.Level1.Config.Value
	case ISIS_LEVEL_2:
		return *circuit.ifConfig.HelloInterval.Level2.Config.Value
	}
	return *circuit.ifConfig.HelloInterval.Config.Value
}

func (circuit *Circuit) helloMultiplier(level IsisLevel) uint16 {
	switch level {
	case ISIS_LEVEL_1:
		return *circuit.ifConfig.HelloMultiplier.Level1.Config.Value
	case ISIS_LEVEL_2:
		return *circuit.ifConfig.HelloMultiplier.Level2.Config.Value
	}
	return *circuit.ifConfig.HelloMultiplier.Config.Value
}

func (circuit *Circuit) helloHoldingTime(level IsisLevel) uint16 {
	return circuit.helloInterval(level) * circuit.helloMultiplier(level)
}

func (circuit *Circuit) circuitType() packet.CircuitType {
	switch *circuit.ifConfig.Config.LevelType {
	case "level-1":
		return packet.CIRCUIT_TYPE_LEVEL1_ONLY
	case "level-2":
		return packet.CIRCUIT_TYPE_LEVEL2_ONLY
	case "level-all":
		return packet.CIRCUIT_TYPE_BOTH_LEVEL1_AND_LEVEL2
	}
	log.Infof("")
	panic("")
	return packet.CIRCUIT_TYPE_RESERVED
}

func (circuit *Circuit) priority(level IsisLevel) uint8 {
	switch level {
	case ISIS_LEVEL_1:
		return *circuit.ifConfig.Priority.Level1.Config.Value
	case ISIS_LEVEL_2:
		return *circuit.ifConfig.Priority.Level2.Config.Value
	}
	return *circuit.ifConfig.Priority.Config.Value
}

func (circuit *Circuit) metric(level IsisLevel) uint32 {
	switch level {
	case ISIS_LEVEL_1:
		return *circuit.ifConfig.Metric.Level1.Config.Value
	case ISIS_LEVEL_2:
		return *circuit.ifConfig.Metric.Level2.Config.Value
	}
	return *circuit.ifConfig.Metric.Config.Value
}

func (circuit *Circuit) configBcast() bool {
	return *circuit.ifConfig.Config.InterfaceType == "broadcast"
}

func (circuit *Circuit) kernelBcast() bool {
	return circuit.ifKernel.IfType == kernel.IF_TYPE_BROADCAST
}

func (circuit *Circuit) ifIndex() int {
	return circuit.ifKernel.IfIndex
}

func (circuit *Circuit) kernelHardwareAddr() []byte {
	return circuit.ifKernel.HardwareAddr
}

func (circuit *Circuit) kernelMtu() int {
	return circuit.ifKernel.Mtu
}

func (circuit *Circuit) kernelUp() bool {
	return circuit.ifKernel.Up
}

func (circuit *Circuit) findAdjacency(lanAddress []byte, adjType AdjType) *Adjacency {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)
	for _, adjacency := range circuit.adjacencyDb {
		if bytes.Equal(adjacency.lanAddress, lanAddress) &&
			adjacency.adjType == adjType {
			return adjacency
		}
	}
	return nil
}

func (circuit *Circuit) addAdjacency(adjacency *Adjacency) error {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)
	adjacencies := make([]*Adjacency, 0)
	for _, adjtmp := range circuit.adjacencyDb {
		if !bytes.Equal(adjtmp.lanAddress, adjacency.lanAddress) ||
			adjtmp.adjType != adjacency.adjType {
			adjacencies = append(adjacencies, adjtmp)
		}
	}
	adjacencies = append(adjacencies, adjacency)
	circuit.adjacencyDb = adjacencies
	return nil
}

func (circuit *Circuit) removeAdjacency(lanAddress []byte, adjType AdjType) error {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)
	adjacencies := make([]*Adjacency, 0)
	for _, adjtmp := range circuit.adjacencyDb {
		if !bytes.Equal(adjtmp.lanAddress, lanAddress) ||
			adjtmp.adjType != adjType {
			adjacencies = append(adjacencies, adjtmp)
		}
	}
	circuit.adjacencyDb = adjacencies
	return nil
}

func (circuit *Circuit) snSender() {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)
	for {
		snp, ok := <-circuit.snSenderCh
		if !ok {
			return
		}
		circuit.sendPdu(snp)
	}
}

func (circuit *Circuit) lsSender() {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)
	for {
		lsp, ok := <-circuit.lsSenderCh
		if !ok {
			return
		}
		circuit.sendPdu(lsp)
		time.Sleep(time.Millisecond * time.Duration(circuit.lspPacingInterval()))
	}
}

func (circuit *Circuit) p2pIihSender() {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)
	timer := time.NewTimer(time.Duration(math.MaxInt64))
	timer.Stop()
	for {
		select {
		case msg := <-(circuit.p2pIihSenderCh):
			switch msg {
			case CIRCUIT_CH_MSG_START:
				log.Debugf("%s: CIRCUIT_CH_MSG_START", circuit.name)
				circuit.sendIih(packet.PDU_TYPE_P2P_IIHP)
				timer.Reset(time.Second * circuit.sendP2pIihInterval())
			case CIRCUIT_CH_MSG_STOP:
				log.Debugf("%s: CIRCUIT_CH_MSG_STOP", circuit.name)
				timer.Stop()
			case CIRCUIT_CH_MSG_EXIT:
				log.Debugf("%s: CIRCUIT_CH_MSG_EXIT", circuit.name)
				goto EXIT
			}
		case <-timer.C:
			log.Debugf("%s: timer.C", circuit.name)
			circuit.sendIih(packet.PDU_TYPE_P2P_IIHP)
			timer.Reset(time.Second * circuit.sendP2pIihInterval())
		}
	}
EXIT:
}

func (circuit *Circuit) l1lIihSender() {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)
	timer := time.NewTimer(time.Duration(math.MaxInt64))
	timer.Stop()
	for {
		select {
		case msg := <-(circuit.l1lIihSenderCh):
			switch msg {
			case CIRCUIT_CH_MSG_START:
				log.Debugf("%s: CIRCUIT_CH_MSG_START", circuit.name)
				d := time.Second * circuit.sendL1lIihInterval() * 2
				if circuit.uptime != nil &&
					circuit.uptime.Add(d).Before(time.Now()) {
					circuit.sendIih(packet.PDU_TYPE_LEVEL1_LAN_IIHP)
				}
				timer.Reset(time.Second * circuit.sendL1lIihInterval())
			case CIRCUIT_CH_MSG_STOP:
				log.Debugf("%s: CIRCUIT_CH_MSG_STOP", circuit.name)
				timer.Stop()
			case CIRCUIT_CH_MSG_EXIT:
				log.Debugf("%s: CIRCUIT_CH_MSG_EXIT", circuit.name)
				goto EXIT
			}
		case <-timer.C:
			log.Debugf("%s: timer.C", circuit.name)
			circuit.sendIih(packet.PDU_TYPE_LEVEL1_LAN_IIHP)
			timer.Reset(time.Second * circuit.sendL1lIihInterval())
		}
	}
EXIT:
}

func (circuit *Circuit) l2lIihSender() {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)
	timer := time.NewTimer(time.Duration(math.MaxInt64))
	timer.Stop()
	for {
		select {
		case msg := <-(circuit.l2lIihSenderCh):
			switch msg {
			case CIRCUIT_CH_MSG_START:
				log.Debugf("%s: CIRCUIT_CH_MSG_START", circuit.name)
				d := time.Second * circuit.sendL2lIihInterval() * 2
				if circuit.uptime != nil &&
					circuit.uptime.Add(d).Before(time.Now()) {
					circuit.sendIih(packet.PDU_TYPE_LEVEL2_LAN_IIHP)
				}
				timer.Reset(time.Second * circuit.sendL2lIihInterval())
			case CIRCUIT_CH_MSG_STOP:
				log.Debugf("%s: CIRCUIT_CH_MSG_STOP", circuit.name)
				timer.Stop()
			case CIRCUIT_CH_MSG_EXIT:
				log.Debugf("%s: CIRCUIT_CH_MSG_EXIT", circuit.name)
				goto EXIT
			}
		case <-timer.C:
			log.Debugf("%s: timer.C", circuit.name)
			circuit.sendIih(packet.PDU_TYPE_LEVEL2_LAN_IIHP)
			timer.Reset(time.Second * circuit.sendL2lIihInterval())
		}
	}
EXIT:
}

func (circuit *Circuit) l1lCsnSender() {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)
	timer := time.NewTimer(time.Duration(math.MaxInt64))
	timer.Stop()
	for {
		select {
		case msg := <-(circuit.l1lCsnSenderCh):
			switch msg {
			case CIRCUIT_CH_MSG_START:
				log.Debugf("%s: CIRCUIT_CH_MSG_START", circuit.name)
				//circuit.sendCsn(packet.PDU_TYPE_LEVEL1_CSNP)
				timer.Reset(time.Second * circuit.sendCsnInterval())
			case CIRCUIT_CH_MSG_STOP:
				log.Debugf("%s: CIRCUIT_CH_MSG_STOP", circuit.name)
				timer.Stop()
			case CIRCUIT_CH_MSG_EXIT:
				log.Debugf("%s: CIRCUIT_CH_MSG_EXIT", circuit.name)
				goto EXIT
			}
		case <-timer.C:
			log.Debugf("%s: timer.C", circuit.name)
			circuit.sendCsn(packet.PDU_TYPE_LEVEL1_CSNP)
			timer.Reset(time.Second * circuit.sendCsnInterval())
		}
	}
EXIT:
}

func (circuit *Circuit) l2lCsnSender() {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)
	timer := time.NewTimer(time.Duration(math.MaxInt64))
	timer.Stop()
	for {
		select {
		case msg := <-(circuit.l2lCsnSenderCh):
			switch msg {
			case CIRCUIT_CH_MSG_START:
				log.Debugf("%s: CIRCUIT_CH_MSG_START", circuit.name)
				//circuit.sendCsn(packet.PDU_TYPE_LEVEL2_CSNP)
				timer.Reset(time.Second * circuit.sendCsnInterval())
			case CIRCUIT_CH_MSG_STOP:
				log.Debugf("%s: CIRCUIT_CH_MSG_STOP", circuit.name)
				timer.Stop()
			case CIRCUIT_CH_MSG_EXIT:
				log.Debugf("%s: CIRCUIT_CH_MSG_EXIT", circuit.name)
				goto EXIT
			}
		case <-timer.C:
			log.Debugf("%s: timer.C", circuit.name)
			circuit.sendCsn(packet.PDU_TYPE_LEVEL2_CSNP)
			timer.Reset(time.Second * circuit.sendCsnInterval())
		}
	}
EXIT:
}

type receiverMessage struct {
	from []byte
	pdu  packet.IsisPdu
}

func (circuit *Circuit) receiver() {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)
	buf := make([]byte, 10240)
	recvCh := make(chan *receiverMessage)
	for {
		select {
		case msg := <-(circuit.receiverCh):
			switch msg {
			case CIRCUIT_CH_MSG_START:
				log.Debugf("%s: CIRCUIT_CH_MSG_START", circuit.name)
				go func() {
					for circuit.receiverState == CIRCUIT_CH_STATE_RUNNING {
						n, from, err := syscall.Recvfrom(circuit.fd, buf, 0)
						if err != nil {
							break
						}
						fromll := from.(*syscall.SockaddrLinklayer)
						fromb := fromll.Addr[0:6]
						llc := 0
						if bytes.Equal(buf[0:3], packet.Llc) {
							llc = 3
						}
						pdu, err := packet.DecodePduFromBytes(buf[0+llc : n])
						if err != nil {
							break
						}
						recvCh <- &receiverMessage{from: fromb, pdu: pdu}
					}
				}()
			case CIRCUIT_CH_MSG_STOP:
				log.Debugf("%s: CIRCUIT_CH_MSG_STOP", circuit.name)
			case CIRCUIT_CH_MSG_EXIT:
				log.Debugf("%s: CIRCUIT_CH_MSG_EXIT", circuit.name)
				goto EXIT
			}
		case rcvMsg := <-recvCh:
			log.Debugf("%s: recvCh", circuit.name)
			if circuit.receiverState != CIRCUIT_CH_STATE_RUNNING {
				log.Debugf("%s: discard", circuit.name)
				break
			}
			switch rcvMsg.pdu.PduType() {
			case packet.PDU_TYPE_LEVEL1_LAN_IIHP, packet.PDU_TYPE_LEVEL2_LAN_IIHP:
				iihPdu := rcvMsg.pdu.(*packet.IihPdu)
				circuit.receiveBcastIih(iihPdu, rcvMsg.from)
			case packet.PDU_TYPE_P2P_IIHP:
				iihPdu := rcvMsg.pdu.(*packet.IihPdu)
				circuit.receiveP2pIih(iihPdu, rcvMsg.from)
			case packet.PDU_TYPE_LEVEL1_LSP, packet.PDU_TYPE_LEVEL2_LSP:
				lsPdu := rcvMsg.pdu.(*packet.LsPdu)
				circuit.receiveLs(lsPdu, rcvMsg.from)
			case packet.PDU_TYPE_LEVEL1_CSNP, packet.PDU_TYPE_LEVEL2_CSNP,
				packet.PDU_TYPE_LEVEL1_PSNP, packet.PDU_TYPE_LEVEL2_PSNP:
				snPdu := rcvMsg.pdu.(*packet.SnPdu)
				circuit.receiveSn(snPdu, rcvMsg.from)
			default:
				log.Debugf("%s: unknown pdu", circuit.name)
			}
		}
	}
EXIT:
}

func (circuit *Circuit) dst(pdu packet.IsisPdu) []byte {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)
	dst := packet.AllIss
	if circuit.configBcast() {
		if pdu.PduType() == packet.PDU_TYPE_LEVEL1_LAN_IIHP ||
			pdu.PduType() == packet.PDU_TYPE_LEVEL1_LSP ||
			pdu.PduType() == packet.PDU_TYPE_LEVEL1_CSNP ||
			pdu.PduType() == packet.PDU_TYPE_LEVEL1_PSNP {
			dst = packet.AllL1Iss
		}
		if pdu.PduType() == packet.PDU_TYPE_LEVEL2_LAN_IIHP ||
			pdu.PduType() == packet.PDU_TYPE_LEVEL2_LSP ||
			pdu.PduType() == packet.PDU_TYPE_LEVEL2_CSNP ||
			pdu.PduType() == packet.PDU_TYPE_LEVEL2_PSNP {
			dst = packet.AllL2Iss
		}
	}
	return dst
}

func (circuit *Circuit) sendPdu(pdu packet.IsisPdu) {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)
	data, err := pdu.Serialize()
	if err != nil {
		log.Infof("Serialize failed")
		return
	}
	buflen := len(data)
	if circuit.kernelBcast() {
		buflen += 3
	}
	buf := make([]byte, buflen)
	if circuit.kernelBcast() {
		copy(buf[0:3], packet.Llc)
		copy(buf[3:], data)
	} else {
		copy(buf, data)
	}
	var dad [8]byte
	dst := circuit.dst(pdu)
	copy(dad[0:6], dst[0:6])
	dad[6] = 0x0
	dad[7] = 0x0
	dstaddr := syscall.SockaddrLinklayer{
		//Protocol: syscall.ETH_P_IP,
		Protocol: htons(uint16(len(buf))),
		Ifindex:  circuit.ifKernel.IfIndex,
		Halen:    uint8(6),
		Addr:     dad,
	}
	err = syscall.Sendto(circuit.fd, buf, 0, &dstaddr)
	if err != nil {
		log.Infof("Sendto failed")
		return
	}
}

func (circuit *Circuit) changed() bool {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)
	changed := false

	for _, level := range ISIS_LEVEL_ALL {
		newIsReachabilities := circuit.newIsReachabilities(level)
		if circuit.isReachabilitiesChanged(level, newIsReachabilities) {
			circuit.isReachabilities[level] = newIsReachabilities
			changed = true
		}
	}

	p2pIihSenderStateOld := circuit.p2pIihSenderState
	l1lIihSenderStateOld := circuit.l1lIihSenderState
	l2lIihSenderStateOld := circuit.l2lIihSenderState
	l1lCsnSenderStateOld := circuit.l1lCsnSenderState
	l2lCsnSenderStateOld := circuit.l2lCsnSenderState
	receiverStateOld := circuit.receiverState
	if (circuit.p2pIihSenderState == CIRCUIT_CH_STATE_SUSPENDED &&
		circuit.l1lIihSenderState == CIRCUIT_CH_STATE_SUSPENDED &&
		circuit.l2lIihSenderState == CIRCUIT_CH_STATE_SUSPENDED &&
		circuit.l1lCsnSenderState == CIRCUIT_CH_STATE_SUSPENDED &&
		circuit.l2lCsnSenderState == CIRCUIT_CH_STATE_SUSPENDED &&
		circuit.receiverState == CIRCUIT_CH_STATE_SUSPENDED) &&
		circuit.ready() {
		log.Debugf("%s: socket open", circuit.name)
		fd, err := isisSocket(circuit.ifKernel)
		if err != nil {
			s := "%s: socketPacket failed: %v"
			log.Infof(s, circuit.name, err)
		}
		circuit.fd = fd
	}
	switch circuit.p2pIihSenderState {
	case CIRCUIT_CH_STATE_RUNNING:
		if !circuit.ready() || circuit.configBcast() {
			circuit.p2pIihSenderCh <- CIRCUIT_CH_MSG_STOP
			circuit.p2pIihSenderState = CIRCUIT_CH_STATE_SUSPENDED
			log.Debugf("%s: p2pIihSenderState RUNNING -> SUSPENDED",
				circuit.name)
		}
	case CIRCUIT_CH_STATE_SUSPENDED:
		if circuit.ready() && !circuit.configBcast() {
			circuit.p2pIihSenderCh <- CIRCUIT_CH_MSG_START
			circuit.p2pIihSenderState = CIRCUIT_CH_STATE_RUNNING
			log.Debugf("%s: p2pIihSenderState SUSPENDED -> RUNNING",
				circuit.name)
		}
	}
	switch circuit.l1lIihSenderState {
	case CIRCUIT_CH_STATE_RUNNING:
		if !circuit.ready() || !circuit.configBcast() || !circuit.level1() {
			circuit.l1lIihSenderCh <- CIRCUIT_CH_MSG_STOP
			circuit.l1lIihSenderState = CIRCUIT_CH_STATE_SUSPENDED
			log.Debugf("%s: l1lIihSenderState RUNNING -> SUSPENDED",
				circuit.name)
		}
	case CIRCUIT_CH_STATE_SUSPENDED:
		if circuit.ready() && circuit.configBcast() && circuit.level1() {
			circuit.l1lIihSenderCh <- CIRCUIT_CH_MSG_START
			circuit.l1lIihSenderState = CIRCUIT_CH_STATE_RUNNING
			log.Debugf("%s: l1lIihSenderState SUSPENDED -> RUNNING",
				circuit.name)
		}
	}
	switch circuit.l2lIihSenderState {
	case CIRCUIT_CH_STATE_RUNNING:
		if !circuit.ready() || !circuit.configBcast() || !circuit.level2() {
			circuit.l2lIihSenderCh <- CIRCUIT_CH_MSG_STOP
			circuit.l2lIihSenderState = CIRCUIT_CH_STATE_SUSPENDED
			log.Debugf("%s: l2lIihSenderState RUNNING -> SUSPENDED",
				circuit.name)
		}
	case CIRCUIT_CH_STATE_SUSPENDED:
		if circuit.ready() && circuit.configBcast() && circuit.level2() {
			circuit.l2lIihSenderCh <- CIRCUIT_CH_MSG_START
			circuit.l2lIihSenderState = CIRCUIT_CH_STATE_RUNNING
			log.Debugf("%s: l2lIihSenderState SUSPENDED -> RUNNING",
				circuit.name)
		}
	}
	switch circuit.l1lCsnSenderState {
	case CIRCUIT_CH_STATE_RUNNING:
		if !circuit.ready() || !circuit.configBcast() || !circuit.designated(ISIS_LEVEL_1) {
			circuit.l1lCsnSenderCh <- CIRCUIT_CH_MSG_STOP
			circuit.l1lCsnSenderState = CIRCUIT_CH_STATE_SUSPENDED
			log.Debugf("%s: l1lCsnSenderState RUNNING -> SUSPENDED",
				circuit.name)
		}
	case CIRCUIT_CH_STATE_SUSPENDED:
		if circuit.ready() && circuit.configBcast() && circuit.designated(ISIS_LEVEL_1) {
			circuit.l1lCsnSenderCh <- CIRCUIT_CH_MSG_START
			circuit.l1lCsnSenderState = CIRCUIT_CH_STATE_RUNNING
			log.Debugf("%s: l1lCsnSenderState SUSPENDED -> RUNNING",
				circuit.name)
		}
	}
	switch circuit.l2lCsnSenderState {
	case CIRCUIT_CH_STATE_RUNNING:
		if !circuit.ready() || !circuit.configBcast() || !circuit.designated(ISIS_LEVEL_2) {
			circuit.l2lCsnSenderCh <- CIRCUIT_CH_MSG_STOP
			circuit.l2lCsnSenderState = CIRCUIT_CH_STATE_SUSPENDED
			log.Debugf("%s: l2lCsnSenderState RUNNING -> SUSPENDED",
				circuit.name)
		}
	case CIRCUIT_CH_STATE_SUSPENDED:
		if circuit.ready() && circuit.configBcast() && circuit.designated(ISIS_LEVEL_2) {
			circuit.l2lCsnSenderCh <- CIRCUIT_CH_MSG_START
			circuit.l2lCsnSenderState = CIRCUIT_CH_STATE_RUNNING
			log.Debugf("%s: l2lCsnSenderState SUSPENDED -> RUNNING",
				circuit.name)
		}
	}
	switch circuit.receiverState {
	case CIRCUIT_CH_STATE_RUNNING:
		if !circuit.ready() {
			circuit.receiverCh <- CIRCUIT_CH_MSG_STOP
			circuit.receiverState = CIRCUIT_CH_STATE_SUSPENDED
			log.Debugf("%s: receiverState RUNNING -> SUSPENDED",
				circuit.name)
		}
	case CIRCUIT_CH_STATE_SUSPENDED:
		if circuit.ready() {
			circuit.receiverCh <- CIRCUIT_CH_MSG_START
			circuit.receiverState = CIRCUIT_CH_STATE_RUNNING
			log.Debugf("%s: receiverState SUSPENDED -> RUNNING",
				circuit.name)
		}
	}
	if (p2pIihSenderStateOld == CIRCUIT_CH_STATE_RUNNING ||
		l1lIihSenderStateOld == CIRCUIT_CH_STATE_RUNNING ||
		l2lIihSenderStateOld == CIRCUIT_CH_STATE_RUNNING ||
		l1lCsnSenderStateOld == CIRCUIT_CH_STATE_RUNNING ||
		l2lCsnSenderStateOld == CIRCUIT_CH_STATE_RUNNING ||
		receiverStateOld == CIRCUIT_CH_STATE_RUNNING) &&
		!circuit.ready() {
		log.Debugf("%s: socket close", circuit.name)
		syscall.Close(circuit.fd)
	}
	return changed
}

func (circuit *Circuit) sortIsReachabilities(isReachabilities []*IsReachability) {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)
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

func (circuit *Circuit) newIsReachabilities(level IsisLevel) []*IsReachability {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)
	new := make([]*IsReachability, 0)
	if !circuit.designated(level) {
		return new
	}
	for _, adjacency := range circuit.adjacencyDb {
		if adjacency.adjState != packet.ADJ_3WAY_STATE_UP {
			continue
		}
		neighborId := make([]byte, len(adjacency.systemId))
		copy(neighborId, adjacency.systemId)
		isr := &IsReachability{
			neighborId: neighborId,
			metric:     0,
			lspNumber:  -1,
		}
		new = append(new, isr)
	}
	for _, ctmp := range circuit.isReachabilities[level] {
		for _, ntmp := range new {
			if bytes.Equal(ntmp.neighborId, ctmp.neighborId) {
				ntmp.lspNumber = ctmp.lspNumber
			}
		}
	}
	circuit.sortIsReachabilities(new)
	return new
}

func (circuit *Circuit) isReachabilitiesChanged(level IsisLevel, new []*IsReachability) bool {
	log.Debugf("enter: %s", circuit.name)
	defer log.Debugf("exit: %s", circuit.name)
	current := circuit.isReachabilities[level]
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
