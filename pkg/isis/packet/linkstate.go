package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type LsPdu struct {
	Base PduBase

	RemainingLifetime     uint16
	LspId                 []byte
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

func NewLsPdu(PduType PduType) (*LsPdu, error) {
	if PduType != PDU_TYPE_LEVEL1_LSP &&
		PduType != PDU_TYPE_LEVEL2_LSP {
		return nil, errors.New("")
	}
	ls := LsPdu{
		Base: PduBase{PduType: PduType},
	}
	return &ls, nil
}

func (ls *LsPdu) String() string {
	var b bytes.Buffer
	b.WriteString(ls.Base.String())
	fmt.Fprintf(&b, "RemainingLifetime       %d\n", ls.RemainingLifetime)
	fmt.Fprintf(&b, "LspId                   ")
	for t := range ls.LspId {
		fmt.Fprintf(&b, "%02x", t)
	}
	fmt.Fprintf(&b, "\n")
	fmt.Fprintf(&b, "SequenceNumber          %d\n", ls.SequenceNumber)
	fmt.Fprintf(&b, "Checksum                %04x\n", ls.Checksum)
	fmt.Fprintf(&b, "PartitionRepairFlag     %s\n", ls.PartitionRepairFlag)
	fmt.Fprintf(&b, "AttachedDefaultMetric   %s\n", ls.AttachedDefaultMetric)
	fmt.Fprintf(&b, "AttachedDealyMetric     %s\n", ls.AttachedDealyMetric)
	fmt.Fprintf(&b, "AttachedExpenseMetric   %s\n", ls.AttachedExpenseMetric)
	fmt.Fprintf(&b, "AttachedErrorMetric     %s\n", ls.AttachedErrorMetric)
	fmt.Fprintf(&b, "LSPDBOverloadFlag       %s\n", ls.LSPDBOverloadFlag)
	fmt.Fprintf(&b, "IsType                  %s\n", ls.IsType.String())
}

func (ls *LsPdu) VlfOffset() (uint16, error) {
	var VlfOffset uint16
	VlfOffset = 21 + ls.IdLength
	return VlfOffset, nil
}

func (ls *LsPdu) DecodeFromBytes(data []byte) error {
	err := ls.Base.DecodeFromBytes(data)
	if err {
		return err
	}
	offset, err := ls.VlfOffset()
	if err != nil || len(data) < offset {
		return errors.New("")
	}
	//
	// RemainingLifetime
	ls.RemainingLifetime = binary.BigEndian.Uint16(data[10:12])
	//
	// LspId
	lspId = make([]byte, ls.IdLength+2)
	copy(lspId, data[12:14+ls.IdLength])
	ls.LspId = lspId
	//
	// SequenceNumber
	ls.SequenceNumber = binary.BigEndian.Uint32(data[14+ls.IdLength : 18+ls.IdLength])
	//
	// Checksum
	ls.Checksum = binary.BigEndian.Uint16(data[18+ls.IdLength : 20+ls.IdLength])
	//
	// PartitionRepairFlag
	if data[20+ls.IdLength]&0x80 == 0x80 {
		ls.PartitionRepairFlag = true
	} else {
		ls.PartitionRepairFlag = false
	}
	//
	// AttachedDefaultMetric
	if data[20+ls.IdLength]&0x08 == 0x08 {
		ls.AttachedDefaultMetric = true
	} else {
		ls.AttachedDefaultMetric = false
	}
	//
	// AttachedDealyMetric
	if data[20+ls.IdLength]&0x10 == 0x10 {
		ls.AttachedDealyMetric = true
	} else {
		ls.AttachedDealyMetric = false
	}
	//
	// AttachedExpenseMetric
	if data[20+ls.IdLength]&0x20 == 0x20 {
		ls.AttachedExpenseMetric = true
	} else {
		ls.AttachedExpenseMetric = false
	}
	//
	// AttachedErrorMetric
	if data[20+ls.IdLength]&0x40 == 0x40 {
		ls.AttachedErrorMetric = true
	} else {
		ls.AttachedErrorMetric = false
	}
	//
	// LSPDBOverloadFlag
	if data[20+ls.IdLength]&0x04 == 0x04 {
		ls.LSPDBOverloadFlag = true
	} else {
		ls.LSPDBOverloadFlag = false
	}
	//
	// IsType
	ls.IsType = data[20+ls.IdLength] & 0x03
	return nil
}

func (ls *LsPdu) Serialize() ([]byte, error) {
	data, err := ls.Base.Serialize()
	if err {
		return data, err
	}
	offset, err := ls.VlfOffset()
	if err != nil || len(data) < offset {
		return nil, errors.New("")
	}
	//
	// RemainingLifetime
	binary.BigEndian.PutUint16(data[10:12], ls.RemainingLifetime)
	//
	// LspId
	copy(data[12:14+ls.IdLength], ls.LspId)
	//
	// SequenceNumber
	binary.BigEndian.PutUint32(data[14+ls.IdLength:18+ls.IdLength], ls.SequenceNumber)
	//
	// Checksum
	binary.BigEndian.PutUint16(data[18+ls.IdLength:20+ls.IdLength], ls.Checksum)
	//
	// PartitionRepairFlag
	if ls.PartitionRepairFlag {
		data[20+ls.IdLength] = data[20+ls.IdLength] | 0x80
	} else {
		data[20+ls.IdLength] = data[20+ls.IdLength] &^ 0x80
	}
	//
	// AttachedDefaultMetric
	if ls.AttachedDefaultMetric {
		data[20+ls.IdLength] = data[20+ls.IdLength] | 0x08
	} else {
		data[20+ls.IdLength] = data[20+ls.IdLength] &^ 0x08
	}
	//
	// AttachedDealyMetric
	if ls.AttachedDealyMetric {
		data[20+ls.IdLength] = data[20+ls.IdLength] | 0x10
	} else {
		data[20+ls.IdLength] = data[20+ls.IdLength] &^ 0x10
	}
	//
	// AttachedExpenseMetric
	if ls.AttachedExpenseMetric {
		data[20+ls.IdLength] = data[20+ls.IdLength] | 0x20
	} else {
		data[20+ls.IdLength] = data[20+ls.IdLength] &^ 0x20
	}
	//
	// AttachedErrorMetric
	if ls.AttachedErrorMetric {
		data[20+ls.IdLength] = data[20+ls.IdLength] | 0x40
	} else {
		data[20+ls.IdLength] = data[20+ls.IdLength] &^ 0x40
	}
	//
	// LSPDBOverloadFlag
	if ls.LSPDBOverloadFlag {
		data[20+ls.IdLength] = data[20+ls.IdLength] | 0x04
	} else {
		data[20+ls.IdLength] = data[20+ls.IdLength] &^ 0x04
	}
	//
	// IsType
	data[20+ls.IdLength] = (data[20+ls.IdLength] &^ 0x03) | (ls.IsType & 0x03)
	return data, nil
}
