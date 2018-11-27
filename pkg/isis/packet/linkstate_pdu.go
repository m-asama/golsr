package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type lsPdu struct {
	base pduBase

	RemainingLifetime     uint16
	lspId                 []byte
	SequenceNumber        uint32
	Checksum              uint16
	PartitionRepairFlag   bool
	AttachedDefaultMetric bool
	AttachedDealyMetric   bool
	AttachedExpenseMetric bool
	AttachedErrorMetric   bool
	LSPDBOverloadFlag     bool
	IsType                IsType
}

func NewLsPdu(pduType PduType) (*lsPdu, error) {
	var lengthIndicator uint8
	if pduType != PDU_TYPE_LEVEL1_LSP &&
		pduType != PDU_TYPE_LEVEL2_LSP {
		return nil, errors.New("NewLsPdu: pduType invalid")
	}
	lengthIndicator = 21 + SYSTEM_ID_LENGTH
	ls := lsPdu{
		base: pduBase{
			lengthIndicator: lengthIndicator,
			pduType:         pduType,
		},
	}
	ls.base.init()
	ls.lspId = make([]byte, 0)
	return &ls, nil
}

func (ls *lsPdu) String() string {
	var b bytes.Buffer
	b.WriteString(ls.base.StringFixed())
	fmt.Fprintf(&b, "RemainingLifetime               %d\n", ls.RemainingLifetime)
	fmt.Fprintf(&b, "lspId                           ")
	for t := range ls.lspId {
		fmt.Fprintf(&b, "%02x", t)
	}
	fmt.Fprintf(&b, "\n")
	fmt.Fprintf(&b, "SequenceNumber                  %d\n", ls.SequenceNumber)
	fmt.Fprintf(&b, "Checksum                        0x%04x\n", ls.Checksum)
	fmt.Fprintf(&b, "PartitionRepairFlag             %t\n", ls.PartitionRepairFlag)
	fmt.Fprintf(&b, "AttachedDefaultMetric           %t\n", ls.AttachedDefaultMetric)
	fmt.Fprintf(&b, "AttachedDealyMetric             %t\n", ls.AttachedDealyMetric)
	fmt.Fprintf(&b, "AttachedExpenseMetric           %t\n", ls.AttachedExpenseMetric)
	fmt.Fprintf(&b, "AttachedErrorMetric             %t\n", ls.AttachedErrorMetric)
	fmt.Fprintf(&b, "LSPDBOverloadFlag               %t\n", ls.LSPDBOverloadFlag)
	fmt.Fprintf(&b, "IsType                          %s\n", ls.IsType.String())
	b.WriteString(ls.base.StringTlv())
	return b.String()
}

func (ls *lsPdu) DecodeFromBytes(data []byte) error {
	err := ls.base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	//
	// RemainingLifetime
	ls.RemainingLifetime = binary.BigEndian.Uint16(data[10:12])
	//
	// LspId
	lspId := make([]byte, ls.base.idLength+2)
	copy(lspId, data[12:14+ls.base.idLength])
	ls.lspId = lspId
	//
	// SequenceNumber
	ls.SequenceNumber = binary.BigEndian.Uint32(data[14+ls.base.idLength : 18+ls.base.idLength])
	//
	// Checksum
	ls.Checksum = binary.BigEndian.Uint16(data[18+ls.base.idLength : 20+ls.base.idLength])
	//
	// PartitionRepairFlag
	if data[20+ls.base.idLength]&0x80 == 0x80 {
		ls.PartitionRepairFlag = true
	} else {
		ls.PartitionRepairFlag = false
	}
	//
	// AttachedDefaultMetric
	if data[20+ls.base.idLength]&0x08 == 0x08 {
		ls.AttachedDefaultMetric = true
	} else {
		ls.AttachedDefaultMetric = false
	}
	//
	// AttachedDealyMetric
	if data[20+ls.base.idLength]&0x10 == 0x10 {
		ls.AttachedDealyMetric = true
	} else {
		ls.AttachedDealyMetric = false
	}
	//
	// AttachedExpenseMetric
	if data[20+ls.base.idLength]&0x20 == 0x20 {
		ls.AttachedExpenseMetric = true
	} else {
		ls.AttachedExpenseMetric = false
	}
	//
	// AttachedErrorMetric
	if data[20+ls.base.idLength]&0x40 == 0x40 {
		ls.AttachedErrorMetric = true
	} else {
		ls.AttachedErrorMetric = false
	}
	//
	// LSPDBOverloadFlag
	if data[20+ls.base.idLength]&0x04 == 0x04 {
		ls.LSPDBOverloadFlag = true
	} else {
		ls.LSPDBOverloadFlag = false
	}
	//
	// IsType
	ls.IsType = IsType(data[20+ls.base.idLength] & 0x03)
	return nil
}

func (ls *lsPdu) Serialize() ([]byte, error) {
	data, err := ls.base.Serialize()
	if err != nil {
		return data, err
	}
	//
	// RemainingLifetime
	binary.BigEndian.PutUint16(data[10:12], ls.RemainingLifetime)
	//
	// LspId
	copy(data[12:14+ls.base.idLength], ls.lspId)
	//
	// SequenceNumber
	binary.BigEndian.PutUint32(data[14+ls.base.idLength:18+ls.base.idLength], ls.SequenceNumber)
	//
	// Checksum
	binary.BigEndian.PutUint16(data[18+ls.base.idLength:20+ls.base.idLength], ls.Checksum)
	//
	// PartitionRepairFlag
	if ls.PartitionRepairFlag {
		data[20+ls.base.idLength] = data[20+ls.base.idLength] | 0x80
	} else {
		data[20+ls.base.idLength] = data[20+ls.base.idLength] &^ 0x80
	}
	//
	// AttachedDefaultMetric
	if ls.AttachedDefaultMetric {
		data[20+ls.base.idLength] = data[20+ls.base.idLength] | 0x08
	} else {
		data[20+ls.base.idLength] = data[20+ls.base.idLength] &^ 0x08
	}
	//
	// AttachedDealyMetric
	if ls.AttachedDealyMetric {
		data[20+ls.base.idLength] = data[20+ls.base.idLength] | 0x10
	} else {
		data[20+ls.base.idLength] = data[20+ls.base.idLength] &^ 0x10
	}
	//
	// AttachedExpenseMetric
	if ls.AttachedExpenseMetric {
		data[20+ls.base.idLength] = data[20+ls.base.idLength] | 0x20
	} else {
		data[20+ls.base.idLength] = data[20+ls.base.idLength] &^ 0x20
	}
	//
	// AttachedErrorMetric
	if ls.AttachedErrorMetric {
		data[20+ls.base.idLength] = data[20+ls.base.idLength] | 0x40
	} else {
		data[20+ls.base.idLength] = data[20+ls.base.idLength] &^ 0x40
	}
	//
	// LSPDBOverloadFlag
	if ls.LSPDBOverloadFlag {
		data[20+ls.base.idLength] = data[20+ls.base.idLength] | 0x04
	} else {
		data[20+ls.base.idLength] = data[20+ls.base.idLength] &^ 0x04
	}
	//
	// IsType
	data[20+ls.base.idLength] = (data[20+ls.base.idLength] &^ 0x03) | (uint8(ls.IsType) & 0x03)
	return data, nil
}
