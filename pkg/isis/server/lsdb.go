package server

import (
	"bytes"
	"errors"
	"sort"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/m-asama/golsr/pkg/isis/packet"
)

type Ls struct {
	pdu       *packet.LsPdu
	origin    bool
	srmFlags  map[int]*time.Time
	ssnFlags  map[int]*time.Time
	generated *time.Time
	expired   *time.Time
}

type Lss []*Ls

func (lss Lss) Len() int {
	return len(lss)
}

func (lss Lss) Swap(i, j int) {
	lss[i], lss[j] = lss[j], lss[i]
}

func (lss Lss) Less(i, j int) bool {
	return bytes.Compare(lss[i].pdu.LspId(), lss[j].pdu.LspId()) < 0
}

func NewLs(pdu *packet.LsPdu, origin bool, generated *time.Time) (*Ls, error) {
	log.Debugf("enter")
	defer log.Debugf("exit")
	ls := Ls{
		pdu:       pdu,
		origin:    origin,
		generated: generated,
	}
	ls.srmFlags = make(map[int]*time.Time)
	ls.ssnFlags = make(map[int]*time.Time)
	return &ls, nil
}

func (isis *IsisServer) lspLevel(lsp *packet.LsPdu) (IsisLevel, error) {
	log.Debugf("enter")
	defer log.Debugf("exit")
	if lsp == nil {
		return 0, errors.New("lsp invalid")
	}
	switch lsp.PduType() {
	case packet.PDU_TYPE_LEVEL1_LSP:
		return ISIS_LEVEL_1, nil
	case packet.PDU_TYPE_LEVEL2_LSP:
		return ISIS_LEVEL_2, nil
	}
	return 0, errors.New("level invalid")
}

func (isis *IsisServer) insertLsp(lsp *packet.LsPdu, origin bool, generated *time.Time) *Ls {
	log.Debugf("enter: lspid=%x origin=%s generated=%s", lsp.LspId(), origin, generated)
	defer log.Debugf("exit: lspid=%x origin=%s generated=%s", lsp.LspId(), origin, generated)
	level, err := isis.lspLevel(lsp)
	if err != nil {
		return nil
	}
	isis.lock.Lock()
	defer isis.lock.Unlock()
	lsDb := make([]*Ls, 0)
	for _, lstmp := range isis.lsDb[level] {
		if !bytes.Equal(lstmp.pdu.LspId(), lsp.LspId()) {
			lsDb = append(lsDb, lstmp)
		}
	}
	ls, _ := NewLs(lsp, origin, generated)
	lsDb = append(lsDb, ls)
	isis.lsDb[level] = lsDb
	return ls
}

func (isis *IsisServer) deleteLsp(ls *Ls) {
	log.Debugf("enter: lspid=%x", ls.pdu.LspId())
	defer log.Debugf("exit: lspid=%x", ls.pdu.LspId())
	level, err := isis.lspLevel(ls.pdu)
	if err != nil {
		return
	}
	isis.lock.Lock()
	defer isis.lock.Unlock()
	lsDb := make([]*Ls, 0)
	for _, lstmp := range isis.lsDb[level] {
		if lstmp != ls {
			lsDb = append(lsDb, lstmp)
		}
	}
	isis.lsDb[level] = lsDb
}

func (isis *IsisServer) lookupLsp(level IsisLevel, lspId []byte) *Ls {
	log.Debugf("enter: level=%s lspid=%x", level, lspId)
	defer log.Debugf("exit: level=%s lspid=%x", level, lspId)
	isis.lock.Lock()
	defer isis.lock.Unlock()
	for _, lstmp := range isis.lsDb[level] {
		if bytes.Equal(lstmp.pdu.LspId(), lspId) {
			return lstmp
		}
	}
	return nil
}

func (isis *IsisServer) originLss(level IsisLevel, nodeId uint8) []*Ls {
	log.Debugf("enter")
	defer log.Debugf("exit")
	isis.lock.Lock()
	defer isis.lock.Unlock()
	lss := make([]*Ls, 0)
	for _, lstmp := range isis.lsDb[level] {
		if !lstmp.origin ||
			!bytes.Equal(lstmp.pdu.LspId()[0:packet.SYSTEM_ID_LENGTH], isis.systemId) ||
			lstmp.pdu.LspId()[packet.NEIGHBOUR_ID_LENGTH-1] != nodeId {
			continue
		}
		lss = append(lss, lstmp)
	}
	sort.Sort(Lss(lss))
	return lss
}
