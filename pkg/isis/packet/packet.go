package packet

import (
	"fmt"
)

type IsisPdu interface {
	String() string
	VlfOffset() (uint16, error)
	DecodeFromBytes(data []byte) error
	Serialize() ([]byte, error)
}

type PduType uint8

const (
	_                        PduType = iota
	PDU_TYPE_LEVEL1_LAN_IIHP         = 0x0f
	PDU_TYPE_LEVEL2_LAN_IIHP         = 0x10
	PDU_TYPE_P2P_IIHP                = 0x11
	PDU_TYPE_LEVEL1_LSP              = 0x12
	PDU_TYPE_LEVEL2_LSP              = 0x14
	PDU_TYPE_LEVEL1_CSNP             = 0x18
	PDU_TYPE_LEVEL2_CSNP             = 0x19
	PDF_TYPE_LEVEL1_PSNP             = 0x1a
	PDF_TYPE_LEVEL2_PSNP             = 0x1b
)

func (pduType PduType) String() string {
	switch pduType {
	case PDU_TYPE_LEVEL1_LAN_IIHP:
		return "PDU_TYPE_LEVEL1_LAN_IIHP"
	case PDU_TYPE_LEVEL2_LAN_IIHP:
		return "PDU_TYPE_LEVEL2_LAN_IIHP"
	case PDU_TYPE_P2P_IIHP:
		return "PDU_TYPE_P2P_IIHP"
	case PDU_TYPE_LEVEL1_LSP:
		return "PDU_TYPE_LEVEL1_LSP"
	case PDU_TYPE_LEVEL2_LSP:
		return "PDU_TYPE_LEVEL2_LSP"
	case PDU_TYPE_LEVEL1_CSNP:
		return "PDU_TYPE_LEVEL1_CSNP"
	case PDU_TYPE_LEVEL2_CSNP:
		return "PDU_TYPE_LEVEL2_CSNP"
	case PDF_TYPE_LEVEL1_PSNP:
		return "PDF_TYPE_LEVEL1_PSNP"
	case PDF_TYPE_LEVEL2_PSNP:
		return "PDF_TYPE_LEVEL2_PSNP"
	}
	return fmt.Sprintf("PduType(%d)", pduType)
}

type CircuitType uint8

const (
	_                                   CircuitType = iota
	CIRCUIT_TYPE_RESERVED                           = 0x00
	CIRCUIT_TYPE_LEVEL1_ONLY                        = 0x01
	CIRCUIT_TYPE_LEVEL2_ONLY                        = 0x02
	CIRCUIT_TYPE_BOTH_LEVEL1_AND_LEVEL2             = 0x03
)

func (circuitType CircuitType) String() string {
	switch circuitType {
	case CIRCUIT_TYPE_RESERVED:
		return "CIRCUIT_TYPE_RESERVED"
	case CIRCUIT_TYPE_LEVEL1_ONLY:
		return "CIRCUIT_TYPE_LEVEL1_ONLY"
	case CIRCUIT_TYPE_LEVEL2_ONLY:
		return "CIRCUIT_TYPE_LEVEL2_ONLY"
	case CIRCUIT_TYPE_BOTH_LEVEL1_AND_LEVEL2:
		return "CIRCUIT_TYPE_BOTH_LEVEL1_AND_LEVEL2"
	}
	return fmt.Sprintf("CircuitType(%d)", circuitType)
}

type IsType uint8

const (
	_                 IsType = iota
	IS_TYPE_LEVEL1_IS        = 0x01
	IS_TYPE_LEVEL2_IS        = 0x03
)

func (isType IsType) String() string {
	switch isType {
	case IS_TYPE_LEVEL1_IS:
		return "IS_TYPE_LEVEL1_IS"
	case IS_TYPE_LEVEL2_IS:
		return "IS_TYPE_LEVEL2_IS"
	}
	return fmt.Sprintf("IsType(%d)", isType)
}
