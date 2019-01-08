package server

import (
	"bytes"
	"os"
	"os/signal"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/m-asama/golsr/internal/pkg/isis/config"
	"github.com/m-asama/golsr/internal/pkg/kernel"
	"github.com/m-asama/golsr/pkg/isis/packet"
)

type IsisLevel uint8

const (
	ISIS_LEVEL_1 IsisLevel = iota
	ISIS_LEVEL_2
	ISIS_LEVEL_NUM
)

var ISIS_LEVEL_ALL = []IsisLevel{ISIS_LEVEL_1, ISIS_LEVEL_2}

func (level *IsisLevel) pduTypeLsp() packet.PduType {
	switch *level {
	case ISIS_LEVEL_1:
		return packet.PDU_TYPE_LEVEL1_LSP
	case ISIS_LEVEL_2:
		return packet.PDU_TYPE_LEVEL2_LSP
	}
	log.Infof("")
	panic("")
	return packet.PduType(0)
}

func (level *IsisLevel) pduTypeCsnp() packet.PduType {
	switch *level {
	case ISIS_LEVEL_1:
		return packet.PDU_TYPE_LEVEL1_CSNP
	case ISIS_LEVEL_2:
		return packet.PDU_TYPE_LEVEL2_CSNP
	}
	log.Infof("")
	panic("")
	return packet.PduType(0)
}

func (level *IsisLevel) pduTypePsnp() packet.PduType {
	switch *level {
	case ISIS_LEVEL_1:
		return packet.PDU_TYPE_LEVEL1_PSNP
	case ISIS_LEVEL_2:
		return packet.PDU_TYPE_LEVEL2_PSNP
	}
	log.Infof("")
	panic("")
	return packet.PduType(0)
}

func (level *IsisLevel) isType() packet.IsType {
	switch *level {
	case ISIS_LEVEL_1:
		return packet.IS_TYPE_LEVEL1_IS
	case ISIS_LEVEL_2:
		return packet.IS_TYPE_LEVEL2_IS
	}
	log.Infof("")
	panic("")
	return packet.IsType(0)
}

func pduType2level(pduType packet.PduType) IsisLevel {
	switch pduType {
	case packet.PDU_TYPE_LEVEL1_LAN_IIHP, packet.PDU_TYPE_LEVEL1_LSP:
		return ISIS_LEVEL_1
	case packet.PDU_TYPE_LEVEL1_CSNP, packet.PDU_TYPE_LEVEL1_PSNP:
		return ISIS_LEVEL_1
	case packet.PDU_TYPE_LEVEL2_LAN_IIHP, packet.PDU_TYPE_LEVEL2_LSP:
		return ISIS_LEVEL_2
	case packet.PDU_TYPE_LEVEL2_CSNP, packet.PDU_TYPE_LEVEL2_PSNP:
		return ISIS_LEVEL_2
	}
	log.Infof("")
	panic("")
	return IsisLevel(ISIS_LEVEL_NUM)
}

type IsisChMsg uint8

const (
	_ IsisChMsg = iota
	ISIS_CH_MSG_ENABLE
	ISIS_CH_MSG_DISABLE
	ISIS_CH_MSG_EXIT
)

type IsisServer struct {
	isisCh     chan IsisChMsg
	decisionCh chan *DecisionChMsg
	updateCh   chan *UpdateChMsg

	configFile string
	configType string
	config     *config.IsisConfig
	kernel     *kernel.KernelStatus

	systemId           []byte
	areaAddresses      [][]byte
	isReachabilities   [ISIS_LEVEL_NUM][]*IsReachability
	ipv4Reachabilities [ISIS_LEVEL_NUM][]*Ipv4Reachability
	ipv6Reachabilities [ISIS_LEVEL_NUM][]*Ipv6Reachability

	lsDb      [ISIS_LEVEL_NUM][]*Ls
	circuitDb map[int]*Circuit

	lock sync.RWMutex
}

func NewIsisServer(configFile, configType string) *IsisServer {
	log.Debugf("enter")
	defer log.Debugf("exit")
	isis := &IsisServer{
		isisCh:        make(chan IsisChMsg),
		decisionCh:    make(chan *DecisionChMsg, 8),
		updateCh:      make(chan *UpdateChMsg, 8),
		configFile:    configFile,
		configType:    configType,
		config:        config.NewIsisConfig(),
		kernel:        kernel.NewKernelStatus(),
		systemId:      make([]byte, packet.SYSTEM_ID_LENGTH),
		areaAddresses: make([][]byte, 0),
		circuitDb:     make(map[int]*Circuit),
	}
	for _, level := range ISIS_LEVEL_ALL {
		isis.isReachabilities[level] = make([]*IsReachability, 0)
		isis.ipv4Reachabilities[level] = make([]*Ipv4Reachability, 0)
		isis.ipv6Reachabilities[level] = make([]*Ipv6Reachability, 0)
		isis.lsDb[level] = make([]*Ls, 0)
	}
	return isis
}

func (isis *IsisServer) Serve(wg *sync.WaitGroup) {
	log.Debugf("enter")
	defer log.Debugf("exit")
	defer wg.Done()

	log.Debugf("")

	var updateWg sync.WaitGroup

	sigCh := make(chan os.Signal, 1)
	configCh := make(chan *config.IsisConfig)
	if isis.configFile != "" {
		updateWg.Add(1)
		go config.Serve(isis.configFile, isis.configType, configCh)
	} else {
		signal.Notify(sigCh, syscall.SIGHUP)
	}

	kernelCh := make(chan *kernel.KernelStatus)
	updateWg.Add(1)
	go kernel.Serve(kernelCh)

	periodicCh := make(chan struct{})
	go isis.periodic(periodicCh)

	go isis.decisionProcess()
	go isis.updateProcess(&updateWg)

	configReady := false
	kernelReady := false
	for {
		select {
		case <-sigCh:
			log.WithFields(log.Fields{
				"Topic": "Config",
			}).Info("Do nothing")
		case msg := <-isis.isisCh:
			switch msg {
			case ISIS_CH_MSG_ENABLE:
				log.Debugf("ISIS_CH_MSG_ENABLE")
			case ISIS_CH_MSG_DISABLE:
				log.Debugf("ISIS_CH_MSG_DISABLE")
			case ISIS_CH_MSG_EXIT:
				log.Debugf("ISIS_CH_MSG_EXIT")
				periodicCh <- struct{}{}
				goto EXIT
			}
		case c := <-configCh:
			isis.configChanged(c)
			if !configReady {
				updateWg.Done()
				configReady = true
			}
		case k := <-kernelCh:
			isis.kernelChanged(k)
			if !kernelReady {
				updateWg.Done()
				kernelReady = true
			}
		}
	}
EXIT:
}

func (isis *IsisServer) Exit() {
	log.Debugf("enter")
	defer log.Debugf("exit")
	isis.isisCh <- ISIS_CH_MSG_EXIT
}

func (isis *IsisServer) SetEnable() {
	log.Debugf("enter")
	defer log.Debugf("exit")
	*isis.config.Config.Enable = true
	isis.isisCh <- ISIS_CH_MSG_ENABLE
}

func (isis *IsisServer) SetDisable() {
	log.Debugf("enter")
	defer log.Debugf("exit")
	*isis.config.Config.Enable = false
	isis.isisCh <- ISIS_CH_MSG_DISABLE
}

func (isis *IsisServer) enable() bool {
	return *isis.config.Config.Enable
}

func (isis *IsisServer) ready() bool {
	ready := true
	if bytes.Equal(isis.systemId, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) {
		ready = false
	}
	if len(isis.areaAddresses) == 0 {
		ready = false
	}
	if !isis.enable() {
		ready = false
	}
	return ready
}

func (isis *IsisServer) level1() bool {
	return *isis.config.Config.LevelType == "level-all" ||
		*isis.config.Config.LevelType == "level-1"
}

func (isis *IsisServer) level1Only() bool {
	return *isis.config.Config.LevelType == "level-1"
}

func (isis *IsisServer) level2() bool {
	return *isis.config.Config.LevelType == "level-all" ||
		*isis.config.Config.LevelType == "level-2"
}

func (isis *IsisServer) level2Only() bool {
	return *isis.config.Config.LevelType == "level-2"
}

func (isis *IsisServer) levelAll() bool {
	return *isis.config.Config.LevelType == "level-all"
}

func (isis *IsisServer) ipv4Enable() bool {
	enable := false
	for _, af := range isis.config.AddressFamilies {
		if *af.Config.AddressFamily == "ipv4" && *af.Config.Enable == true {
			enable = true
		}
	}
	return enable
}

func (isis *IsisServer) ipv6Enable() bool {
	enable := false
	for _, af := range isis.config.AddressFamilies {
		if *af.Config.AddressFamily == "ipv6" && *af.Config.Enable == true {
			enable = true
		}
	}
	return enable
}

func (isis *IsisServer) lspMtu() uint16 {
	return *isis.config.Config.LspMtu
}

func (isis *IsisServer) lspLifetime() uint16 {
	return *isis.config.Config.LspLifetime
}

func (isis *IsisServer) lspRefresh() uint16 {
	return *isis.config.Config.LspRefresh
}

func (isis *IsisServer) metricType(level IsisLevel) string {
	switch level {
	case ISIS_LEVEL_1:
		return *isis.config.MetricType.Level1.Config.Value
	case ISIS_LEVEL_2:
		return *isis.config.MetricType.Level2.Config.Value
	}
	return *isis.config.MetricType.Config.Value
}

func (isis *IsisServer) wide(level IsisLevel) bool {
	return isis.metricType(level) == "wide-only" ||
		isis.metricType(level) == "both"
}

func (isis *IsisServer) wideOnly(level IsisLevel) bool {
	return isis.metricType(level) == "wide-only"
}

func (isis *IsisServer) old(level IsisLevel) bool {
	return isis.metricType(level) == "old-only" ||
		isis.metricType(level) == "both"
}

func (isis *IsisServer) oldOnly(level IsisLevel) bool {
	return isis.metricType(level) == "old-only"
}

func (isis *IsisServer) both(level IsisLevel) bool {
	return isis.metricType(level) == "both"
}

func (isis *IsisServer) matchAreaAddresses(areaAddresses [][]byte) bool {
	log.Debugf("enter")
	defer log.Debugf("exit")
	if areaAddresses == nil {
		return false
	}
	for _, remoteAa := range areaAddresses {
		for _, localAa := range isis.areaAddresses {
			if bytes.Equal(remoteAa, localAa) {
				return true
			}
		}
	}
	return false
}

func (isis *IsisServer) getIfKernelByName(name string) *kernel.Interface {
	log.Debugf("enter")
	defer log.Debugf("exit")
	for _, ifKernel := range isis.kernel.Interfaces {
		if ifKernel.Name == name {
			return ifKernel
		}
	}
	return nil
}

func (isis *IsisServer) findCircuitByIfIndex(ifIndex int) *Circuit {
	log.Debugf("enter")
	defer log.Debugf("exit")
	for _, circuit := range isis.circuitDb {
		if circuit.ifKernel.IfIndex == ifIndex {
			return circuit
		}
	}
	return nil
}

func (isis *IsisServer) addCircuit(name string, ifConfig *config.Interface) {
	log.Debugf("enter: %s", name)
	defer log.Debugf("exit: %s", name)
	ifKernel := isis.getIfKernelByName(name)
	if ifKernel == nil {
		log.Infof("not such interface %s", name)
		return
	}
	if _, ok := isis.circuitDb[ifKernel.IfIndex]; ok {
		log.Infof("interface %s already exists", name)
		return
	}
	circuit := NewCircuit(isis, ifKernel, ifConfig)
	circuit.Serve()
	circuit.SetEnable()
	isis.circuitDb[ifKernel.IfIndex] = circuit
}

func (isis *IsisServer) removeCircuit(name string) {
	log.Debugf("enter: %s", name)
	defer log.Debugf("exit: %s", name)
	var circuit *Circuit
	for _, tmp := range isis.circuitDb {
		if *tmp.ifConfig.Config.Name == name {
			circuit = tmp
		}
	}
	if circuit == nil {
		return
	}
	circuit.SetDisable()
	circuit.Exit()
	delete(isis.circuitDb, circuit.ifKernel.IfIndex)
}

func (isis *IsisServer) configChanged(newConfig *config.IsisConfig) {
	log.Debugf("enter")
	defer log.Debugf("exit")
	//s.fillConfigDefaults(newConfig)
	added := make(map[string]*config.Interface)
	removed := make(map[string]*config.Interface)
	for _, iface := range isis.config.Interfaces {
		removed[*iface.Config.Name] = iface
	}
	for _, iface := range newConfig.Interfaces {
		if _, ok := removed[*iface.Config.Name]; ok {
			delete(removed, *iface.Config.Name)
		} else {
			added[*iface.Config.Name] = iface
		}
	}
	for name, _ := range removed {
		log.Debugf("remove: %s", name)
		isis.removeCircuit(name)
	}
	for name, iface := range added {
		log.Debugf("add: %s", name)
		isis.addCircuit(name, iface)
	}
	for _, tmp := range isis.circuitDb {
		for _, iface := range newConfig.Interfaces {
			if *tmp.ifConfig.Config.Name == *iface.Config.Name {
				tmp.ifConfig = iface
			}
		}
	}
	isis.config = newConfig
	isis.updateCh <- &UpdateChMsg{
		msgType: UPDATE_CH_MSG_TYPE_CONFIG_CHANGED,
	}
}

func (isis *IsisServer) kernelChanged(newKernel *kernel.KernelStatus) {
	log.Debugf("enter")
	defer log.Debugf("exit")
	removed := make(map[string]*config.Interface)
	for _, iface := range isis.config.Interfaces {
		removed[*iface.Config.Name] = iface
	}
	for _, iface := range newKernel.Interfaces {
		if _, ok := removed[iface.Name]; ok {
			delete(removed, iface.Name)
		}
	}
	for name, _ := range removed {
		log.Debugf("remove: %s", name)
		isis.removeCircuit(name)
	}
	for _, tmp := range isis.circuitDb {
		for _, iface := range newKernel.Interfaces {
			if tmp.ifKernel.IfIndex == iface.IfIndex {
				tmp.ifKernel = iface
				if tmp.name != tmp.ifKernel.Name {
					log.Debugf("renamed %s to %s",
						tmp.name, tmp.ifKernel.Name)
					tmp.name = tmp.ifKernel.Name
					*tmp.ifConfig.Config.Name = tmp.ifKernel.Name
				}
			}
		}
	}
	isis.kernel = newKernel
	isis.updateCh <- &UpdateChMsg{
		msgType: UPDATE_CH_MSG_TYPE_KERNEL_CHANGED,
	}
}
