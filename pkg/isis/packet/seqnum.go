package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type SnPdu struct {
	Base PduBase

	SourceId   []byte
	StartLspId []byte // CSN
	EndLspId   []byte //CSN
}

func NewSnPdu(PduType PduType) (*SnPdu, error) {
	if PduType != PDU_TYPE_LEVEL1_CSNP &&
		PduType != PDU_TYPE_LEVEL2_CSNP &&
		PduType != PDF_TYPE_LEVEL1_PSNP &&
		PduType != PDF_TYPE_LEVEL2_PSNP {
		return nil, errors.New("")
	}
	sn := SnPdu{
		Base: PduBase{PduType: PduType},
	}
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
	if PduType == PDU_TYPE_LEVEL1_CSNP ||
		PduType == PDU_TYPE_LEVEL2_CSNP {
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

func (sn *SnPdu) VlfOffset() (uint16, error) {
	var VlfOffset uint16
	switch sn.Base.PduType {
	case PDU_TYPE_LEVEL1_CSNP, PDU_TYPE_LEVEL2_CSNP:
		VlfOffset = 15 + sn.Base.IdLength*3
	case PDF_TYPE_LEVEL1_PSNP, PDF_TYPE_LEVEL2_PSNP:
		VlfOffset = 11 + sn.Base.IdLength
	default:
		return 0, errors.New("")
	}
	return VlfOffset, nil
}

func (sn *SnPdu) DecodeFromBytes(data []byte) error {
	err := sn.Base.DecodeFromBytes(data)
	if err {
		return err
	}
	offset, err := sn.VlfOffset()
	if err != nil || len(data) < offset {
		return errors.New("")
	}
	//
	// SourceId
	sourceId = make([]byte, sn.Base.IdLength+1)
	copy(sourceId, data[10:11+sn.Base.IdLength])
	sn.SourceId = sourceId
	if PduType == PDU_TYPE_LEVEL1_CSNP ||
		PduType == PDU_TYPE_LEVEL2_CSNP {
		//
		// StartLspId
		startLspId = make([]byte, sn.Base.IdLength+2)
		copy(startLspId, data[11+sn.Base.IdLength:13+sn.Base.IdLength*2])
		sn.StartLspId = startLspId
		//
		// EndLspId
		endLspId = make([]byte, sn.Base.IdLength+2)
		copy(endLspId, data[13+sn.Base.IdLength*2:15+sn.Base.IdLength*3])
		sn.EndLspId = endLspId
	}
	return nil
}

func (sn *SnPdu) Serialize() ([]byte, error) {
	data, err := sn.Base.Serialize()
	if err {
		return data, err
	}
	offset, err := sn.VlfOffset()
	if err != nil || len(data) < offset {
		return nil, errors.New("")
	}
	//
	// SourceId
	copy(data[10:11+sn.Base.IdLength], sn.SourceId)
	if PduType == PDU_TYPE_LEVEL1_CSNP ||
		PduType == PDU_TYPE_LEVEL2_CSNP {
		//
		// StartLspId
		copy(data[11+sn.Base.IdLength:13+sn.Base.IdLength*2], sn.StartLspId)
		//
		// EndLspId
		copy(data[13+sn.Base.IdLength*2:15+sn.Base.IdLength*3], sn.EndLspId)
	}
	return data, nil
}
