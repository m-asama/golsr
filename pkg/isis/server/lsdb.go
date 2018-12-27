package server

import (
	"bytes"
	"time"

	_ "github.com/sirupsen/logrus"

	"github.com/m-asama/golsr/pkg/isis/packet"
)

type Ls struct {
	pdu    *packet.LsPdu
	origin bool
	//srmFlags  []int
	//ssnFlags  []int
	srmFlags  map[int]*time.Time
	ssnFlags  map[int]*time.Time
	generated *time.Time
	expired   *time.Time
}

func NewLs(pdu *packet.LsPdu, origin bool, generated *time.Time) (*Ls, error) {
	ls := Ls{
		pdu:       pdu,
		origin:    origin,
		generated: generated,
	}
	ls.srmFlags = make(map[int]*time.Time)
	ls.ssnFlags = make(map[int]*time.Time)
	return &ls, nil
}

func (isis *IsisServer) insertLevel1Lsp(lsp *packet.LsPdu, origin bool, generated *time.Time) *Ls {
	if lsp.PduType() != packet.PDU_TYPE_LEVEL1_LSP {
		return nil
	}
	isis.lock.Lock()
	defer isis.lock.Unlock()
	level1LsDb := make([]*Ls, 0)
	for _, lstmp := range isis.level1LsDb {
		if !bytes.Equal(lstmp.pdu.LspId(), lsp.LspId()) {
			level1LsDb = append(level1LsDb, lstmp)
		}
	}
	ls, _ := NewLs(lsp, origin, generated)
	level1LsDb = append(level1LsDb, ls)
	isis.level1LsDb = level1LsDb
	return ls
}

func (isis *IsisServer) insertLevel2Lsp(lsp *packet.LsPdu, origin bool, generated *time.Time) *Ls {
	if lsp.PduType() != packet.PDU_TYPE_LEVEL2_LSP {
		return nil
	}
	isis.lock.Lock()
	defer isis.lock.Unlock()
	level2LsDb := make([]*Ls, 0)
	for _, lstmp := range isis.level2LsDb {
		if !bytes.Equal(lstmp.pdu.LspId(), lsp.LspId()) {
			level2LsDb = append(level2LsDb, lstmp)
		}
	}
	ls, _ := NewLs(lsp, origin, generated)
	level2LsDb = append(level2LsDb, ls)
	isis.level2LsDb = level2LsDb
	return ls
}

func (isis *IsisServer) insertLsp(lsp *packet.LsPdu, origin bool, generated *time.Time) *Ls {
	switch lsp.PduType() {
	case packet.PDU_TYPE_LEVEL1_LSP:
		return isis.insertLevel1Lsp(lsp, origin, generated)
	case packet.PDU_TYPE_LEVEL2_LSP:
		return isis.insertLevel2Lsp(lsp, origin, generated)
	}
	return nil
}

func (isis *IsisServer) deleteLsp(ls *Ls) {
	isis.lock.Lock()
	defer isis.lock.Unlock()
	//
	level1LsDb := make([]*Ls, 0)
	for _, lstmp := range isis.level1LsDb {
		if lstmp != ls {
			level1LsDb = append(level1LsDb, lstmp)
		}
	}
	isis.level1LsDb = level1LsDb
	//
	level2LsDb := make([]*Ls, 0)
	for _, lstmp := range isis.level2LsDb {
		if lstmp != ls {
			level2LsDb = append(level2LsDb, lstmp)
		}
	}
	isis.level2LsDb = level2LsDb
}

func (isis *IsisServer) lookupLevel1Lsp(lspId []byte) *Ls {
	isis.lock.Lock()
	defer isis.lock.Unlock()
	for _, lstmp := range isis.level1LsDb {
		if bytes.Equal(lstmp.pdu.LspId(), lspId) {
			return lstmp
		}
	}
	return nil
}

func (isis *IsisServer) lookupLevel2Lsp(lspId []byte) *Ls {
	isis.lock.Lock()
	defer isis.lock.Unlock()
	for _, lstmp := range isis.level2LsDb {
		if bytes.Equal(lstmp.pdu.LspId(), lspId) {
			return lstmp
		}
	}
	return nil
}

func (isis *IsisServer) lookupLsp(isType packet.IsType, lspId []byte) *Ls {
	switch isType {
	case packet.IS_TYPE_LEVEL1_IS:
		return isis.lookupLevel1Lsp(lspId)
	case packet.IS_TYPE_LEVEL2_IS:
		return isis.lookupLevel2Lsp(lspId)
	}
	return nil
}
