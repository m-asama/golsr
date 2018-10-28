package packet

import (
	"encoding/binary"
	"errors"
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
}

func (base *PduBase) String() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "IRPDiscriminator        %02x\n", base.IRPDiscriminator)
	fmt.Fprintf(&b, "LengthIndicator         %02x\n", base.LengthIndicator)
	fmt.Fprintf(&b, "VerProtoIdExtension     %02x\n", base.VerProtoIdExtension)
	fmt.Fprintf(&b, "IdLength                %d\n", base.IdLength)
	fmt.Fprintf(&b, "PduType                 %s\n", base.PduType.String())
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
		return errors.New("")
	}
	base.IRPDiscriminator = data[0]
	base.LengthIndicator = data[1]
	base.VerProtoIdExtension = data[2]
	base.IdLength = data[3]
	base.PduType = data[4]
	base.Version = data[5]
	base.Reserved = data[6]
	base.MaximumAreaAddress = data[7]
	switch base.PduType {
	case PDU_TYPE_LEVEL1_LAN_IIHP, PDU_TYPE_LEVEL2_LAN_IIHP, PDU_TYPE_P2P_IIHP:
		if len(data) < 13+base.IdLength {
			return errors.New("")
		}
		base.PduLength = binary.BigEndian.Uint16(data[11+base.IdLength : 13+base.IdLength])
	default:
		if len(data) < 10 {
			return errors.New("")
		}
		base.PduLength = binary.BigEndian.Uint16(data[8:10])
	}
	return nil
}

func (base *PduBase) Serialize() ([]byte, error) {
	data := make([]byte, PduLength)
	data[0] = base.IRPDiscriminator
	data[1] = base.LengthIndicator
	data[2] = base.VerProtoIdExtension
	data[3] = base.IdLength
	data[4] = base.PduType
	data[5] = base.Version
	data[6] = base.Reserved
	data[7] = base.MaximumAreaAddress
	switch base.PduType {
	case PDU_TYPE_LEVEL1_LAN_IIHP, PDU_TYPE_LEVEL2_LAN_IIHP, PDU_TYPE_P2P_IIHP:
		binary.BigEndian.PutUint16(data[11+base.IdLength:13+base.IdLength], base.PduLength)
	default:
		binary.BigEndian.PutUint16(data[8:10], base.PduLength)
	}
	return data, nil
}
