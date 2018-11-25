package packet

import (
	"bytes"
	"errors"
	"fmt"
)

type SnPdu struct {
	Base PduBase

	SourceId   []byte
	StartLspId []byte // CSN
	EndLspId   []byte // CSN
}

func NewSnPdu(pduType PduType, idLength uint8) (*SnPdu, error) {
	if pduType != PDU_TYPE_LEVEL1_CSNP &&
		pduType != PDU_TYPE_LEVEL2_CSNP &&
		pduType != PDF_TYPE_LEVEL1_PSNP &&
		pduType != PDF_TYPE_LEVEL2_PSNP {
		return nil, errors.New("NewSnPdu: pduType invalid")
	}
	var lengthIndicator uint8
	switch pduType {
	case PDU_TYPE_LEVEL1_CSNP, PDU_TYPE_LEVEL2_CSNP:
		lengthIndicator = 15 + idLength*3
	case PDF_TYPE_LEVEL1_PSNP, PDF_TYPE_LEVEL2_PSNP:
		lengthIndicator = 11 + idLength
	}
	sn := SnPdu{
		Base: PduBase{
			LengthIndicator: lengthIndicator,
			IdLength:        idLength,
			PduType:         pduType,
		},
	}
	sn.Base.Init()
	sn.SourceId = make([]byte, 0)
	sn.StartLspId = make([]byte, 0)
	sn.EndLspId = make([]byte, 0)
	return &sn, nil
}

func (sn *SnPdu) String() string {
	var b bytes.Buffer
	b.WriteString(sn.Base.String())
	fmt.Fprintf(&b, "SourceId                ")
	for t := range sn.SourceId {
		fmt.Fprintf(&b, "%02x", t)
	}
	fmt.Fprintf(&b, "\n")
	if sn.Base.PduType == PDU_TYPE_LEVEL1_CSNP ||
		sn.Base.PduType == PDU_TYPE_LEVEL2_CSNP {
		fmt.Fprintf(&b, "StartLspId              ")
		for t := range sn.StartLspId {
			fmt.Fprintf(&b, "%02x", t)
		}
		fmt.Fprintf(&b, "\n")
		fmt.Fprintf(&b, "EndLspId                ")
		for t := range sn.EndLspId {
			fmt.Fprintf(&b, "%02x", t)
		}
		fmt.Fprintf(&b, "\n")
	}
	return b.String()
}

func (sn *SnPdu) DecodeFromBytes(data []byte) error {
	err := sn.Base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	//
	// SourceId
	sourceId := make([]byte, sn.Base.IdLength+1)
	copy(sourceId, data[10:11+sn.Base.IdLength])
	sn.SourceId = sourceId
	if sn.Base.PduType == PDU_TYPE_LEVEL1_CSNP ||
		sn.Base.PduType == PDU_TYPE_LEVEL2_CSNP {
		//
		// StartLspId
		startLspId := make([]byte, sn.Base.IdLength+2)
		copy(startLspId, data[11+sn.Base.IdLength:13+sn.Base.IdLength*2])
		sn.StartLspId = startLspId
		//
		// EndLspId
		endLspId := make([]byte, sn.Base.IdLength+2)
		copy(endLspId, data[13+sn.Base.IdLength*2:15+sn.Base.IdLength*3])
		sn.EndLspId = endLspId
	}
	return nil
}

func (sn *SnPdu) Serialize() ([]byte, error) {
	data, err := sn.Base.Serialize()
	if err != nil {
		return data, err
	}
	//
	// SourceId
	copy(data[10:11+sn.Base.IdLength], sn.SourceId)
	if sn.Base.PduType == PDU_TYPE_LEVEL1_CSNP ||
		sn.Base.PduType == PDU_TYPE_LEVEL2_CSNP {
		//
		// StartLspId
		copy(data[11+sn.Base.IdLength:13+sn.Base.IdLength*2], sn.StartLspId)
		//
		// EndLspId
		copy(data[13+sn.Base.IdLength*2:15+sn.Base.IdLength*3], sn.EndLspId)
	}
	return data, nil
}
