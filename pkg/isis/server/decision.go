package server

import (
	"bytes"
	"fmt"

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

func (isis *IsisServer) decisionProcess() {
	log.Debugf("")
	for {
		msg := <-isis.decisionCh
		log.Debugf("%s", msg)
		switch msg.msgType {
		case DECISION_CH_MSG_TYPE_DO:
		case DECISION_CH_MSG_TYPE_EXIT:
			goto EXIT
		}
	}
EXIT:
}
