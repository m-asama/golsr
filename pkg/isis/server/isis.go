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
	_ IsisLevel = iota
	ISIS_LEVEL_1
	ISIS_LEVEL_2
)

type IsisChMsg uint8

const (
	_ IsisChMsg = iota
	ISIS_CH_MSG_ENABLE
	ISIS_CH_MSG_DISABLE
	ISIS_CH_MSG_EXIT
)

type IsReachability struct {
	neighborId []byte
	metric     uint32
	lspNumber  int
}

type Ipv4Reachability struct {
	ipv4Prefix   uint32
	prefixLength uint8
	metric       uint32
	lspNumber    int
}

type Ipv6Reachability struct {
	ipv6Prefix   [4]uint32
	prefixLength uint8
	metric       uint32
	lspNumber    int
}

type IsisServer struct {
	isisCh     chan IsisChMsg
	decisionCh chan *DecisionChMsg
	updateCh   chan *UpdateChMsg

	configFile string
	configType string
	config     *config.IsisConfig
	kernel     *kernel.KernelStatus

	systemId                 []byte
	areaAddresses            [][]byte
	level1IsReachabilities   []*IsReachability
	level2IsReachabilities   []*IsReachability
	level1Ipv4Reachabilities []*Ipv4Reachability
	level2Ipv4Reachabilities []*Ipv4Reachability
	level1Ipv6Reachabilities []*Ipv6Reachability
	level2Ipv6Reachabilities []*Ipv6Reachability

	level1LsDb []*Ls
	level2LsDb []*Ls
	circuitDb  map[int]*Circuit

	lock sync.RWMutex
}

func NewIsisServer(configFile, configType string) *IsisServer {
	s := &IsisServer{
		isisCh:                   make(chan IsisChMsg),
		decisionCh:               make(chan *DecisionChMsg, 8),
		updateCh:                 make(chan *UpdateChMsg, 8),
		configFile:               configFile,
		configType:               configType,
		config:                   config.NewIsisConfig(),
		kernel:                   kernel.NewKernelStatus(),
		systemId:                 make([]byte, packet.SYSTEM_ID_LENGTH),
		areaAddresses:            make([][]byte, 0),
		level1IsReachabilities:   make([]*IsReachability, 0),
		level2IsReachabilities:   make([]*IsReachability, 0),
		level1Ipv4Reachabilities: make([]*Ipv4Reachability, 0),
		level2Ipv4Reachabilities: make([]*Ipv4Reachability, 0),
		level1Ipv6Reachabilities: make([]*Ipv6Reachability, 0),
		level2Ipv6Reachabilities: make([]*Ipv6Reachability, 0),
		level1LsDb:               make([]*Ls, 0),
		level2LsDb:               make([]*Ls, 0),
		circuitDb:                make(map[int]*Circuit),
	}
	return s
}

func (isis *IsisServer) Serve(wg *sync.WaitGroup) {
	defer wg.Done()

	log.Debugf("")

	sigCh := make(chan os.Signal, 1)
	configCh := make(chan *config.IsisConfig)
	if isis.configFile != "" {
		go config.ReadConfigfileServe(isis.configFile, isis.configType, configCh)
	} else {
		signal.Notify(sigCh, syscall.SIGHUP)
	}

	kernelCh := make(chan *kernel.KernelStatus)
	go kernel.Serve(kernelCh)

	periodicCh := make(chan struct{})
	go isis.periodic(periodicCh)

	go isis.decisionProcess()
	go isis.updateProcess()

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
		case k := <-kernelCh:
			isis.kernelChanged(k)
		}
	}
EXIT:
}

func (isis *IsisServer) Exit() {
	log.Debugf("")
	isis.isisCh <- ISIS_CH_MSG_EXIT
}

func (isis *IsisServer) SetEnable() {
	log.Debugf("")
	*isis.config.Config.Enable = true
	isis.isisCh <- ISIS_CH_MSG_ENABLE
}

func (isis *IsisServer) SetDisable() {
	log.Debugf("")
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
	for _, ifKernel := range isis.kernel.Interfaces {
		if ifKernel.Name == name {
			return ifKernel
		}
	}
	return nil
}

func (isis *IsisServer) findCircuitByIfIndex(ifIndex int) *Circuit {
	for _, circuit := range isis.circuitDb {
		if circuit.ifKernel.IfIndex == ifIndex {
			return circuit
		}
	}
	return nil
}

func (isis *IsisServer) addCircuit(name string, ifConfig *config.Interface) {
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
	log.Debug("")
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
	log.Debug("")
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
