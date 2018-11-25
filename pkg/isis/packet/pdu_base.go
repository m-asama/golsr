package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type PduBase struct {
	OriginalData []byte

	IRPDiscriminator    uint8
	LengthIndicator     uint8
	VerProtoIdExtension uint8
	IdLength            uint8
	PduType             PduType
	Version             uint8
	Reserved            uint8
	MaximumAreaAddress  uint8
	PduLength           uint16

	Tlvs []IsisTlv
}

func (base *PduBase) Init() {
	base.OriginalData = make([]byte, 0)

	base.IRPDiscriminator = 0x83
	base.VerProtoIdExtension = 0x01
	base.Version = 0x01

	base.Tlvs = make([]IsisTlv, 0)
}

func (base *PduBase) String() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "IRPDiscriminator        %02x\n", base.IRPDiscriminator)
	fmt.Fprintf(&b, "LengthIndicator         %02x\n", base.LengthIndicator)
	fmt.Fprintf(&b, "VerProtoIdExtension     %02x\n", base.VerProtoIdExtension)
	fmt.Fprintf(&b, "IdLength                %d\n", base.IdLength)
	fmt.Fprintf(&b, "PduType                 %s(%d)\n", base.PduType.String(), base.PduType)
	fmt.Fprintf(&b, "Version                 %02x\n", base.Version)
	fmt.Fprintf(&b, "Reserved                %02x\n", base.Reserved)
	fmt.Fprintf(&b, "MaximumAreaAddress      %d\n", base.MaximumAreaAddress)
	fmt.Fprintf(&b, "PduLength               %d\n", base.PduLength)
	return b.String()
}

func (base *PduBase) DecodeFromBytes(data []byte) error {
	base.OriginalData = make([]byte, len(data))
	copy(base.OriginalData, data)
	if len(data) < 8 {
		return errors.New("PduBase.DecodeFromBytes: data length too short")
	}
	base.IRPDiscriminator = data[0]
	base.LengthIndicator = data[1]
	base.VerProtoIdExtension = data[2]
	base.IdLength = data[3]
	if base.IdLength == 0 {
		base.IdLength = 6
	}
	if base.IdLength == 255 {
		base.IdLength = 0
	}
	base.PduType = PduType(data[4])
	base.Version = data[5]
	base.Reserved = data[6]
	base.MaximumAreaAddress = data[7]
	if base.MaximumAreaAddress == 0 {
		base.MaximumAreaAddress = 3
	}
	switch base.PduType {
	case PDU_TYPE_LEVEL1_LAN_IIHP, PDU_TYPE_LEVEL2_LAN_IIHP, PDU_TYPE_P2P_IIHP:
		if len(data) < int(13+base.IdLength) {
			return errors.New("PduBase.DecodeFromBytes: data length too short")
		}
		base.PduLength = binary.BigEndian.Uint16(data[11+base.IdLength : 13+base.IdLength])
	default:
		if len(data) < 10 {
			return errors.New("PduBase.DecodeFromBytes: data length too short")
		}
		base.PduLength = binary.BigEndian.Uint16(data[8:10])
	}
	if len(data) != int(base.PduLength) {
		return errors.New("PduBase.DecodeFromBytes: data length mismatch")
	}
	return nil
}

func (base *PduBase) Serialize() ([]byte, error) {
	var pduLength uint16
	var tlvs [][]byte
	pduLength = uint16(base.LengthIndicator)
	tlvs = make([][]byte, len(base.Tlvs))
	for i, tlv := range base.Tlvs {
		var err error
		tlvs[i], err = tlv.Serialize()
		if err != nil {
			return nil, err
		}
		pduLength += uint16(len(tlvs[i]))
	}
	base.PduLength = pduLength
	data := make([]byte, base.PduLength)
	data[0] = base.IRPDiscriminator
	data[1] = base.LengthIndicator
	data[2] = base.VerProtoIdExtension
	data[3] = base.IdLength
	if base.IdLength == 0 {
		data[3] = 255
	}
	if base.IdLength == 6 {
		data[3] = 0
	}
	data[4] = uint8(base.PduType)
	data[5] = base.Version
	data[6] = base.Reserved
	data[7] = base.MaximumAreaAddress
	if base.MaximumAreaAddress == 3 {
		data[7] = 0
	}
	switch base.PduType {
	case PDU_TYPE_LEVEL1_LAN_IIHP, PDU_TYPE_LEVEL2_LAN_IIHP, PDU_TYPE_P2P_IIHP:
		binary.BigEndian.PutUint16(data[11+base.IdLength:13+base.IdLength], base.PduLength)
	default:
		binary.BigEndian.PutUint16(data[8:10], base.PduLength)
	}
	i := int(base.LengthIndicator)
	for _, tlv := range tlvs {
		copy(data[i:i+len(tlv)], tlv)
		i += len(tlv)
	}
	return data, nil
}

func DecodePduFromBytes(data []byte) (IsisPdu, error) {
	var pdu IsisPdu
	if len(data) < 5 {
		return nil, errors.New("DecodePduFromBytes: data length too short")
	}
	idLength := data[3]
	if idLength == 0 {
		idLength = 6
	}
	if idLength == 255 {
		idLength = 0
	}
	pduType := PduType(data[4])
	var err error
	switch pduType {
	case PDU_TYPE_LEVEL1_LAN_IIHP, PDU_TYPE_LEVEL2_LAN_IIHP, PDU_TYPE_P2P_IIHP:
		pdu, err = NewIihPdu(pduType, idLength)
	case PDU_TYPE_LEVEL1_LSP, PDU_TYPE_LEVEL2_LSP:
		pdu, err = NewLsPdu(pduType, idLength)
	case PDU_TYPE_LEVEL1_CSNP, PDU_TYPE_LEVEL2_CSNP, PDF_TYPE_LEVEL1_PSNP, PDF_TYPE_LEVEL2_PSNP:
		pdu, err = NewSnPdu(pduType, idLength)
	}
	if err != nil {
		return nil, err
	}
	pdu.DecodeFromBytes(data)
	return pdu, nil
}
