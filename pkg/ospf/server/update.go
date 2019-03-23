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
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"
)

type UpdateChMsgType uint8

const (
	_ UpdateChMsgType = iota
	UPDATE_CH_MSG_TYPE_CONFIG_CHANGED
	UPDATE_CH_MSG_TYPE_KERNEL_CHANGED
	UPDATE_CH_MSG_TYPE_OSPF_ENABLE
	UPDATE_CH_MSG_TYPE_OSPF_DISABLE
	UPDATE_CH_MSG_TYPE_CIRCUIT_ENABLE
	UPDATE_CH_MSG_TYPE_CIRCUIT_DISABLE
	UPDATE_CH_MSG_TYPE_ADJACENCY_UP
	UPDATE_CH_MSG_TYPE_ADJACENCY_DOWN
	UPDATE_CH_MSG_TYPE_LSDB_CHANGED
	UPDATE_CH_MSG_TYPE_EXIT
)

func (msgType UpdateChMsgType) String() string {
	switch msgType {
	case UPDATE_CH_MSG_TYPE_CONFIG_CHANGED:
		return "UPDATE_CH_MSG_TYPE_CONFIG_CHANGED"
	case UPDATE_CH_MSG_TYPE_KERNEL_CHANGED:
		return "UPDATE_CH_MSG_TYPE_KERNEL_CHANGED"
	case UPDATE_CH_MSG_TYPE_OSPF_ENABLE:
		return "UPDATE_CH_MSG_TYPE_OSPF_ENABLE"
	case UPDATE_CH_MSG_TYPE_OSPF_DISABLE:
		return "UPDATE_CH_MSG_TYPE_OSPF_DISABLE"
	case UPDATE_CH_MSG_TYPE_CIRCUIT_ENABLE:
		return "UPDATE_CH_MSG_TYPE_CIRCUIT_ENABLE"
	case UPDATE_CH_MSG_TYPE_CIRCUIT_DISABLE:
		return "UPDATE_CH_MSG_TYPE_CIRCUIT_DISABLE"
	case UPDATE_CH_MSG_TYPE_ADJACENCY_UP:
		return "UPDATE_CH_MSG_TYPE_ADJACENCY_UP"
	case UPDATE_CH_MSG_TYPE_ADJACENCY_DOWN:
		return "UPDATE_CH_MSG_TYPE_ADJACENCY_DOWN"
	case UPDATE_CH_MSG_TYPE_LSDB_CHANGED:
		return "UPDATE_CH_MSG_TYPE_LSDB_CHANGED"
	case UPDATE_CH_MSG_TYPE_EXIT:
		return "UPDATE_CH_MSG_TYPE_EXIT"
	}
	log.Infof("")
	panic("")
	return fmt.Sprintf("UpdateChMsgType(%d)", msgType)
}

type UpdateChMsg struct {
	msgType UpdateChMsgType
}

func (msg *UpdateChMsg) String() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s", msg.msgType.String())
	return b.String()
}

var updateChSendCount int
var updateChSendCountLock sync.RWMutex

func (ospf *OspfServer) updateChSend(msg *UpdateChMsg) {
	go func() {
		updateChSendCountLock.Lock()
		updateChSendCount++
		updateChSendCountLock.Unlock()
		log.Debugf("updateChSend[%d]: begin", updateChSendCount)
		ospf.updateCh <- msg
		log.Debugf("updateChSend[%d]: end", updateChSendCount)
	}()
}

func (ospf *OspfServer) updateProcess(wg *sync.WaitGroup) {
	log.Debugf("enter")
	defer log.Debugf("exit")
	wg.Wait()
	for {
		msg := <-ospf.updateCh
		log.Infof("%s", msg)
		switch msg.msgType {
		case UPDATE_CH_MSG_TYPE_CONFIG_CHANGED:
		case UPDATE_CH_MSG_TYPE_KERNEL_CHANGED:
		case UPDATE_CH_MSG_TYPE_OSPF_ENABLE:
		case UPDATE_CH_MSG_TYPE_OSPF_DISABLE:
		case UPDATE_CH_MSG_TYPE_EXIT:
			goto EXIT
		}
	}
EXIT:
}
