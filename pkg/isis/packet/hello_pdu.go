package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
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

func NewIihPdu(pduType PduType, idLength uint8) (*IihPdu, error) {
	if pduType != PDU_TYPE_LEVEL1_LAN_IIHP &&
		pduType != PDU_TYPE_LEVEL2_LAN_IIHP &&
		pduType != PDU_TYPE_P2P_IIHP {
		return nil, errors.New("NewIihPdu: pduType invalid")
	}
	var lengthIndicator uint8
	switch pduType {
	case PDU_TYPE_LEVEL1_LAN_IIHP, PDU_TYPE_LEVEL2_LAN_IIHP:
		lengthIndicator = 15 + idLength*2
	case PDU_TYPE_P2P_IIHP:
		lengthIndicator = 14 + idLength
	}
	iih := IihPdu{
		Base: PduBase{
			LengthIndicator: lengthIndicator,
			IdLength:        idLength,
			PduType:         pduType,
		},
	}
	iih.Base.Init()
	iih.SourceId = make([]byte, 0)
	iih.LanId = make([]byte, 0)
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
	if iih.Base.PduType == PDU_TYPE_LEVEL1_LAN_IIHP ||
		iih.Base.PduType == PDU_TYPE_LEVEL2_LAN_IIHP {
		fmt.Fprintf(&b, "Priority                %d\n", iih.Priority)
		fmt.Fprintf(&b, "LanId                   ")
		for t := range iih.LanId {
			fmt.Fprintf(&b, "%02x", t)
		}
		fmt.Fprintf(&b, "\n")
	}
	if iih.Base.PduType == PDU_TYPE_P2P_IIHP {
		fmt.Fprintf(&b, "LocalCircuitId          %02x\n", iih.LocalCircuitId)
	}
	return b.String()
}

func (iih *IihPdu) DecodeFromBytes(data []byte) error {
	err := iih.Base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	//
	// CircuitType
	iih.CircuitType = CircuitType(data[8])
	//
	// SourceId
	sourceId := make([]byte, iih.Base.IdLength)
	copy(sourceId, data[9:9+iih.Base.IdLength])
	iih.SourceId = sourceId
	//
	// HoldingTime
	iih.HoldingTime = binary.BigEndian.Uint16(data[9+iih.Base.IdLength : 11+iih.Base.IdLength])
	switch iih.Base.PduType {
	case PDU_TYPE_LEVEL1_LAN_IIHP, PDU_TYPE_LEVEL2_LAN_IIHP:
		//
		// Priority
		iih.Priority = data[13+iih.Base.IdLength]
		//
		// LanId
		lanId := make([]byte, iih.Base.IdLength+1)
		copy(lanId, data[14+iih.Base.IdLength:15+iih.Base.IdLength*2])
		iih.LanId = lanId
	case PDU_TYPE_P2P_IIHP:
		//
		// LocalCircuitId
		iih.LocalCircuitId = data[13+iih.Base.IdLength]
	default:
		return errors.New("IihPdu.DecodeFromBytes: PduType invalid")
	}
	return nil
}

func (iih *IihPdu) Serialize() ([]byte, error) {
	data, err := iih.Base.Serialize()
	if err != nil {
		return data, err
	}
	//
	// CircuitType
	data[8] = uint8(iih.CircuitType)
	//
	// SourceId
	copy(data[9:9+iih.Base.IdLength], iih.SourceId)
	//
	// HoldingTime
	binary.BigEndian.PutUint16(data[9+iih.Base.IdLength:11+iih.Base.IdLength], iih.HoldingTime)
	switch iih.Base.PduType {
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
		return nil, errors.New("IihPdu.Serialize: PduType invalid")
	}
	return data, nil
}
