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
			//isis.checkFlags()
			counter++
			timer.Reset(started.Add(time.Second * counter).Sub(time.Now()))
		}
	}
EXIT:
}
