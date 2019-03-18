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
	"time"

	log "github.com/sirupsen/logrus"
)

func (isis *IsisServer) lsDbIter(ls *Ls) bool {
	log.Debugf("enter")
	defer log.Debugf("exit")
	changed := false
	if ls.pdu.RemainingLifetime > 0 {
		ls.pdu.RemainingLifetime--
	}
	if ls.pdu.RemainingLifetime == 0 {
		if ls.expired == nil {
			expired := time.Now()
			ls.expired = &expired
			changed = true
		}
		if ls.expired.Before(time.Now().Add(-ZERO_AGE_LIFETIME)) {
			isis.deleteLsp(ls, true)
		}
	}
	return changed
}

func (isis *IsisServer) lsDbWalk() bool {
	log.Debugf("enter")
	defer log.Debugf("exit")
	isis.lock.Lock()
	defer isis.lock.Unlock()
	changed := false
	for _, level := range ISIS_LEVEL_ALL {
		for _, ls := range isis.lsDb[level] {
			if isis.lsDbIter(ls) {
				changed = true
			}
		}
	}
	return changed
}

func (isis *IsisServer) adjDbWalk() bool {
	log.Debugf("enter")
	defer log.Debugf("exit")
	isis.lock.Lock()
	defer isis.lock.Unlock()
	changed := false
	for _, circuit := range isis.circuitDb {
		for _, adjacency := range circuit.adjacencyDb {
			if adjacency.holdingTime > 0 {
				adjacency.holdingTime--
			}
			if adjacency.holdingTime == 0 {
				circuit.removeAdjacency(adjacency.lanAddress, adjacency.adjType)
				circuit.isis.updateChSend(&UpdateChMsg{
					msgType:   UPDATE_CH_MSG_TYPE_ADJACENCY_DOWN,
					adjacency: adjacency,
				})
				changed = true
			}
		}
	}
	return changed
}

func (isis *IsisServer) periodic(doneCh chan struct{}) {
	log.Debugf("enter")
	defer log.Debugf("exit")
	timer := time.NewTimer(0)
	started := time.Now()
	var counter time.Duration
	for {
		select {
		case <-doneCh:
			goto EXIT
		case <-timer.C:
			isis.lsDbWalk()
			isis.adjDbWalk()
			counter++
			timer.Reset(started.Add(time.Second * counter).Sub(time.Now()))
		}
	}
EXIT:
}
