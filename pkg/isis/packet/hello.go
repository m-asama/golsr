package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type IihPdu struct {
	Base PduBase

	CircuitType    CircuitType
	SourceId       []byte
	HoldingTime    uint16
	Priority       uint8  // LAN
	LanId          []byte // LAN
	LocalCircuitId uint8  // P2P
}

func NewIihPdu(PduType PduType) (*IihPdu, error) {
	if PduType != PDU_TYPE_LEVEL1_LAN_IIHP &&
		PduType != PDU_TYPE_LEVEL2_LAN_IIHP &&
		PduType != PDU_TYPE_P2P_IIHP {
		return nil, errors.New("")
	}
	iih := IihPdu{
		Base: PduBase{PduType: PduType},
	}
	return &iih, nil
}

func (iih *IihPdu) String() string {
	var b bytes.Buffer
	b.WriteString(iih.Base.String())
	fmt.Fprintf(&b, "CircuitType             %s\n", iih.CircuitType.String())
	fmt.Fprintf(&b, "SourceId                ")
	for t := range iih.SourceId {
		fmt.Fprintf(&b, "%02x", t)
	}
	fmt.Fprintf(&b, "\n")
	fmt.Fprintf(&b, "HoldingTime             %d\n", iih.HoldingTime)
	if PduType == PDU_TYPE_LEVEL1_LAN_IIHP ||
		PduType == PDU_TYPE_LEVEL2_LAN_IIHP {
		fmt.Fprintf(&b, "Priority                %d\n", iih.Priority)
		fmt.Fprintf(&b, "LanId                   ")
		for t := range iih.LanId {
			fmt.Fprintf(&b, "%02x", t)
		}
		fmt.Fprintf(&b, "\n")
	}
	if PduType == PDU_TYPE_P2P_IIHP {
		fmt.Fprintf(&b, "LocalCircuitId          %02x\n", iih.LocalCircuitId)
	}
	return b.String()
}

func (iih *IihPdu) VlfOffset() (uint16, error) {
	var VlfOffset uint16
	switch iih.Base.PduType {
	case PDU_TYPE_LEVEL1_LAN_IIHP, PDU_TYPE_LEVEL2_LAN_IIHP:
		VlfOffset = 15 + iih.Base.IdLength*2
	case PDU_TYPE_P2P_IIHP:
		VlfOffset = 14 + iih.Base.IdLength
	default:
		return 0, errors.New("")
	}
	return VlfOffset, nil
}

func (iih *IihPdu) DecodeFromBytes(data []byte) error {
	err := iih.Base.DecodeFromBytes(data)
	if err {
		return err
	}
	offset, err := iih.VlfOffset()
	if err != nil || len(data) < offset {
		return errors.New("")
	}
	//
	// CircuitType
	iih.CircuitType = data[8]
	//
	// SourceId
	sourceId = make([]byte, iih.Base.IdLength)
	copy(sourceId, data[9:9+iih.Base.IdLength])
	iih.SourceId = sourceId
	//
	// HoldingTime
	iih.HoldingTime = binary.BigEndian.Uint16(data[9+iih.IdLength : 11+iih.IdLength])
	switch iih.PduType {
	case PDU_TYPE_LEVEL1_LAN_IIHP, PDU_TYPE_LEVEL2_LAN_IIHP:
		//
		// Priority
		iih.Priority = data[13+iih.Base.IdLength]
		//
		// LanId
		lanId = make([]byte, iih.Base.IdLength+1)
		copy(lanId, data[14+iih.Base.IdLength:15+iih.Base.IdLength*2])
		iih.LanId = lanId
	case PDU_TYPE_P2P_IIHP:
		//
		// LocalCircuitId
		iih.LocalCircuitId = data[13+iih.Base.IdLength]
	default:
		return errors.New("")
	}
	return nil
}

func (iih *IihPdu) Serialize() ([]byte, error) {
	data, err := iih.Base.Serialize()
	if err {
		return data, err
	}
	offset, err := iih.VlfOffset()
	if err != nil || len(data) < offset {
		return nil, errors.New("")
	}
	//
	// CircuitType
	data[8] = iih.CircuitType
	//
	// SourceId
	copy(data[9:9+iih.Base.IdLength], iih.SourceId)
	//
	// HoldingTime
	binary.BigEndian.PutUint16(data[9+iih.IdLength:11+iih.IdLength], iih.HoldingTime)
	switch iih.PduType {
	case PDU_TYPE_LEVEL1_LAN_IIHP, PDU_TYPE_LEVEL2_LAN_IIHP:
		//
		// Priority
		data[13+iih.Base.IdLength] = iih.Priority
		//
		// LanId
		copy(data[14+iih.Base.IdLength:15+iih.Base.IdLength*2], iih.LanId)
	case PDU_TYPE_P2P_IIHP:
		//
		// LocalCircuitId
		data[13+iih.Base.IdLength] = iih.LocalCircuitId
	default:
		return nil, errors.New("")
	}
	return data, nil
}
