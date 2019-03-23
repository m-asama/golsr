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
	"os"
	"os/signal"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/m-asama/golsr/internal/pkg/kernel"
	"github.com/m-asama/golsr/internal/pkg/ospf/config"
	_ "github.com/m-asama/golsr/pkg/ospf/packet"
)

type OspfChMsg uint8

const (
	_ OspfChMsg = iota
	OSPF_CH_MSG_EXIT
)

type OspfServer struct {
	ospfCh     chan OspfChMsg
	decisionCh chan *DecisionChMsg
	updateCh   chan *UpdateChMsg

	configFile string
	configType string
	config     *config.OspfConfig
	kernel     *kernel.KernelStatus

	lock sync.RWMutex
}

func NewOspfServer(configFile, configType string) *OspfServer {
	log.Debugf("enter")
	defer log.Debugf("exit")
	ospf := &OspfServer{
		ospfCh:     make(chan OspfChMsg),
		decisionCh: make(chan *DecisionChMsg, 8),
		updateCh:   make(chan *UpdateChMsg, 8),
		configFile: configFile,
		configType: configType,
		config:     config.NewOspfConfig(),
		kernel:     kernel.NewKernelStatus(),
	}
	return ospf
}

func (ospf *OspfServer) Serve(wg *sync.WaitGroup) {
	log.Debugf("enter")
	defer log.Debugf("exit")
	defer wg.Done()

	log.Debugf("")

	var updateWg sync.WaitGroup

	sigCh := make(chan os.Signal, 1)
	configCh := make(chan *config.OspfConfig)
	if ospf.configFile != "" {
		updateWg.Add(1)
		go config.Serve(ospf.configFile, ospf.configType, configCh)
	} else {
		signal.Notify(sigCh, syscall.SIGHUP)
	}

	kernelCh := make(chan *kernel.KernelStatus)
	updateWg.Add(1)
	go kernel.Serve(kernelCh)

	periodicCh := make(chan struct{})
	go ospf.periodic(periodicCh)

	go ospf.decisionProcess()
	go ospf.updateProcess(&updateWg)

	configReady := false
	kernelReady := false
	for {
		select {
		case <-sigCh:
			log.WithFields(log.Fields{
				"Topic": "Config",
			}).Info("Do nothing")
		case msg := <-ospf.ospfCh:
			switch msg {
			case OSPF_CH_MSG_EXIT:
				log.Debugf("OSPF_CH_MSG_EXIT")
				periodicCh <- struct{}{}
				goto EXIT
			}
		case c := <-configCh:
			ospf.handleConfigChanged(c)
			if !configReady {
				updateWg.Done()
				configReady = true
			}
		case k := <-kernelCh:
			ospf.handleKernelChanged(k)
			if !kernelReady {
				updateWg.Done()
				kernelReady = true
			}
		}
	}
EXIT:
}

func (ospf *OspfServer) Exit() {
	log.Debugf("enter")
	defer log.Debugf("exit")
	ospf.ospfCh <- OSPF_CH_MSG_EXIT
}

func (ospf *OspfServer) SetEnable() {
	log.Debugf("enter")
	defer log.Debugf("exit")
	*ospf.config.Config.Enable = true
	ospf.updateChSend(&UpdateChMsg{
		msgType: UPDATE_CH_MSG_TYPE_OSPF_ENABLE,
	})
}

func (ospf *OspfServer) SetDisable() {
	log.Debugf("enter")
	defer log.Debugf("exit")
	*ospf.config.Config.Enable = false
	ospf.updateChSend(&UpdateChMsg{
		msgType: UPDATE_CH_MSG_TYPE_OSPF_DISABLE,
	})
}

func (ospf *OspfServer) enable() bool {
	return *ospf.config.Config.Enable
}

func (ospf *OspfServer) handleConfigChanged(newConfig *config.OspfConfig) {
	log.Debugf("enter")
	defer log.Debugf("exit")
	/*
		added := make(map[string]*config.Interface)
		removed := make(map[string]*config.Interface)
		for _, iface := range ospf.config.Interfaces {
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
			ospf.removeCircuit(name)
		}
		for name, iface := range added {
			log.Debugf("add: %s", name)
			ospf.addCircuit(name, iface)
		}
		for _, tmp := range ospf.circuitDb {
			for _, iface := range newConfig.Interfaces {
				if *tmp.ifConfig.Config.Name == *iface.Config.Name {
					tmp.ifConfig = iface
				}
			}
		}
		ospf.config = newConfig
		ospf.updateChSend(&UpdateChMsg{
			msgType: UPDATE_CH_MSG_TYPE_CONFIG_CHANGED,
		})
	*/
}

func (ospf *OspfServer) handleKernelChanged(newKernel *kernel.KernelStatus) {
	log.Debugf("enter")
	defer log.Debugf("exit")
	/*
		removed := make(map[string]*config.Interface)
		for _, iface := range ospf.config.Interfaces {
			removed[*iface.Config.Name] = iface
		}
		for _, iface := range newKernel.Interfaces {
			if _, ok := removed[iface.Name]; ok {
				delete(removed, iface.Name)
			}
		}
		for name, _ := range removed {
			log.Debugf("remove: %s", name)
			ospf.removeCircuit(name)
		}
		for _, tmp := range ospf.circuitDb {
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
		ospf.kernel = newKernel
		ospf.updateChSend(&UpdateChMsg{
			msgType: UPDATE_CH_MSG_TYPE_KERNEL_CHANGED,
		})
	*/
}
