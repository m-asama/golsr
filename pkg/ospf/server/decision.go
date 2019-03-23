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

type DecisionChMsgType uint8

const (
	_ DecisionChMsgType = iota
	DECISION_CH_MSG_TYPE_DO
	DECISION_CH_MSG_TYPE_EXIT
)

func (msgType DecisionChMsgType) String() string {
	switch msgType {
	case DECISION_CH_MSG_TYPE_DO:
		return "DECISION_CH_MSG_TYPE_DO"
	case DECISION_CH_MSG_TYPE_EXIT:
		return "DECISION_CH_MSG_TYPE_EXIT"
	}
	log.Infof("")
	panic("")
	return fmt.Sprintf("DecisionChMsgType(%d)", msgType)
}

type DecisionChMsg struct {
	msgType DecisionChMsgType
}

func (msg *DecisionChMsg) String() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s", msg.msgType.String())
	return b.String()
}

var decisionChSendCount int
var decisionChSendCountLock sync.RWMutex

func (ospf *OspfServer) decisionChSend(msg *DecisionChMsg) {
	go func() {
		decisionChSendCountLock.Lock()
		decisionChSendCount++
		decisionChSendCountLock.Unlock()
		log.Debugf("decisionChSend[%d]: begin", decisionChSendCount)
		ospf.decisionCh <- msg
		log.Debugf("decisionChSend[%d]: end", decisionChSendCount)
	}()
}

func (ospf *OspfServer) decisionProcess() {
	log.Debugf("enter")
	defer log.Debugf("exit")
	for {
		msg := <-ospf.decisionCh
		switch msg.msgType {
		case DECISION_CH_MSG_TYPE_DO:
		case DECISION_CH_MSG_TYPE_EXIT:
			goto EXIT
		}
	}
EXIT:
}
