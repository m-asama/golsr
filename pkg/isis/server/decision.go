package server

import (
	"bytes"
	"fmt"
	"time"

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

func (isis *IsisServer) spf(level IsisLevel, cancelSpfCh, doneSpfCh chan struct{}) {
	log.Debugf("enter: %s", level)
	defer log.Debugf("exit: %s", level)
	for i := 0; i < 10; i++ {
		select {
		case <-cancelSpfCh:
			goto CANCEL
		default:
			time.Sleep(time.Second * 1)
		}
	}
CANCEL:
	doneSpfCh <- struct{}{}
}

func (isis *IsisServer) routeCalculator(level IsisLevel, doCh chan struct{}, doneCh chan struct{}) {
	log.Debugf("enter: %s", level)
	defer log.Debugf("exit: %s", level)
	for {
		<-doCh
		cancelSpfCh := make(chan struct{})
		doneSpfCh := make(chan struct{})
		go isis.spf(level, cancelSpfCh, doneSpfCh)
		select {
		case <-doCh:
			doCh <- struct{}{}
			log.Debugf("REDO: %s", level)
			cancelSpfCh <- struct{}{}
			<-doneSpfCh
			goto REDO
		case <-doneSpfCh:
			log.Debugf("DONE: %s", level)
		}
	REDO:
		doneCh <- struct{}{}
	}
}

func (isis *IsisServer) decisionProcess() {
	log.Debugf("enter")
	defer log.Debugf("exit")
	var doCh [ISIS_LEVEL_NUM]chan struct{}
	var doneCh [ISIS_LEVEL_NUM]chan struct{}
	for _, level := range ISIS_LEVEL_ALL {
		doCh[level] = make(chan struct{}, 8)
		doneCh[level] = make(chan struct{})
		go isis.routeCalculator(level, doCh[level], doneCh[level])
	}
	for {
		var redo bool
		var level1Done bool
		var level2Done bool
		msg := <-isis.decisionCh
		redo = false
	REDO:
		switch msg.msgType {
		case DECISION_CH_MSG_TYPE_DO:
			for _, level := range ISIS_LEVEL_ALL {
				doCh[level] <- struct{}{}
			}
			if redo {
				if !level1Done {
					<-doneCh[ISIS_LEVEL_1]
				}
				if !level2Done {
					<-doneCh[ISIS_LEVEL_2]
				}
			}
			level1Done = false
			level2Done = false
			for !level1Done || !level2Done {
				select {
				case <-doneCh[ISIS_LEVEL_1]:
					level1Done = true
				case <-doneCh[ISIS_LEVEL_2]:
					level2Done = true
				case msg = <-isis.decisionCh:
					redo = true
					goto REDO
				}
			}
		case DECISION_CH_MSG_TYPE_EXIT:
			goto EXIT
		}
	}
EXIT:
}
