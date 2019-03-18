//
// Copyright (C) 2019-2019 Masakazu Asama.
// Copyright (C) 2019-2019 Ginzado Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type pduBase struct {
	originalData []byte

	irpDiscriminator    uint8
	lengthIndicator     uint8
	verProtoIdExtension uint8
	idLength            uint8
	pduType             PduType
	version             uint8
	reserved            uint8
	maximumAreaAddress  uint8
	pduLength           uint16

	tlvs []IsisTlv
}

func (base *pduBase) init() {
	base.originalData = make([]byte, 0)

	base.irpDiscriminator = 0x83
	base.verProtoIdExtension = 0x01
	base.idLength = SYSTEM_ID_LENGTH
	base.version = 0x01
	base.maximumAreaAddress = 0x03

	base.tlvs = make([]IsisTlv, 0)
}

func (base *pduBase) valid() bool {
	if base.irpDiscriminator != 0x83 ||
		base.verProtoIdExtension != 0x01 ||
		base.idLength != SYSTEM_ID_LENGTH ||
		base.version != 0x01 ||
		base.maximumAreaAddress != 0x03 {
		return false
	}
	return true
}

func (base *pduBase) StringFixed() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "irpDiscriminator                0x%02x\n", base.irpDiscriminator)
	fmt.Fprintf(&b, "lengthIndicator                 0x%02x\n", base.lengthIndicator)
	fmt.Fprintf(&b, "verProtoIdExtension             0x%02x\n", base.verProtoIdExtension)
	fmt.Fprintf(&b, "idLength                        %d\n", base.idLength)
	fmt.Fprintf(&b, "pduType                         %s(%d)\n", base.pduType.String(), base.pduType)
	fmt.Fprintf(&b, "version                         0x%02x\n", base.version)
	fmt.Fprintf(&b, "reserved                        0x%02x\n", base.reserved)
	fmt.Fprintf(&b, "maximumAreaAddress              %d\n", base.maximumAreaAddress)
	fmt.Fprintf(&b, "pduLength                       %d\n", base.pduLength)
	return b.String()
}

func (base *pduBase) StringTlv() string {
	var b bytes.Buffer
	for i, tlv := range base.tlvs {
		fmt.Fprintf(&b, "TLV[%d]\n", i)
		fmt.Fprintf(&b, tlv.String())
	}
	return b.String()
}

func (base *pduBase) DecodeFromBytes(data []byte) error {
	base.originalData = make([]byte, len(data))
	copy(base.originalData, data)
	if len(data) < 8 {
		return errors.New("pduBase.DecodeFromBytes: data length too short")
	}
	base.irpDiscriminator = data[0]
	base.lengthIndicator = data[1]
	base.verProtoIdExtension = data[2]
	base.idLength = data[3]
	if base.idLength == 0 {
		base.idLength = 6
	}
	if base.idLength == 255 {
		base.idLength = 0
	}
	base.pduType = PduType(data[4])
	base.version = data[5]
	base.reserved = data[6]
	base.maximumAreaAddress = data[7]
	if base.maximumAreaAddress == 0 {
		base.maximumAreaAddress = 3
	}
	switch base.pduType {
	case PDU_TYPE_LEVEL1_LAN_IIHP, PDU_TYPE_LEVEL2_LAN_IIHP, PDU_TYPE_P2P_IIHP:
		if len(data) < int(13+SYSTEM_ID_LENGTH) {
			return errors.New("pduBase.DecodeFromBytes: data length too short")
		}
		base.pduLength = binary.BigEndian.Uint16(data[11+SYSTEM_ID_LENGTH : 13+SYSTEM_ID_LENGTH])
	default:
		if len(data) < 10 {
			return errors.New("pduBase.DecodeFromBytes: data length too short")
		}
		base.pduLength = binary.BigEndian.Uint16(data[8:10])
	}
	if len(data) != int(base.pduLength) {
		s := fmt.Sprintf("pduBase.DecodeFromBytes: data length mismatch %d %d", len(data), int(base.pduLength))
		return errors.New(s)
	}

	// TLV
	if len(data) >= int(base.lengthIndicator) {
		i := int(base.lengthIndicator)
		for i < int(base.pduLength) {
			if int(base.pduLength) < i+2 {
				return errors.New("pduBase.DecodeFromBytes: data length short")
			}
			t := TlvCode(data[i+0])
			l := int(data[i+1])
			tlv, err := NewTlv(t)
			if err != nil {
				return err
			}
			if int(base.pduLength) < i+2+l {
				return errors.New("pduBase.DecodeFromBytes: data length short")
			}
			err = tlv.DecodeFromBytes(data[i : i+2+l])
			if err != nil {
				return err
			}
			base.tlvs = append(base.tlvs, tlv)
			i += 2 + l
		}
	}

	return nil
}

func (base *pduBase) Serialize() ([]byte, error) {
	var pduLength uint16
	var tlvs [][]byte
	pduLength = uint16(base.lengthIndicator)
	tlvs = make([][]byte, len(base.tlvs))
	for i, tlv := range base.tlvs {
		var err error
		tlvs[i], err = tlv.Serialize()
		if err != nil {
			return nil, err
		}
		pduLength += uint16(len(tlvs[i]))
	}
	base.pduLength = pduLength
	data := make([]byte, base.pduLength)
	data[0] = base.irpDiscriminator
	data[1] = base.lengthIndicator
	data[2] = base.verProtoIdExtension
	data[3] = base.idLength
	if base.idLength == 0 {
		data[3] = 255
	}
	if base.idLength == 6 {
		data[3] = 0
	}
	data[4] = uint8(base.pduType)
	data[5] = base.version
	data[6] = base.reserved
	data[7] = base.maximumAreaAddress
	if base.maximumAreaAddress == 3 {
		data[7] = 0
	}
	switch base.pduType {
	case PDU_TYPE_LEVEL1_LAN_IIHP, PDU_TYPE_LEVEL2_LAN_IIHP, PDU_TYPE_P2P_IIHP:
		binary.BigEndian.PutUint16(data[11+SYSTEM_ID_LENGTH:13+SYSTEM_ID_LENGTH], base.pduLength)
	default:
		binary.BigEndian.PutUint16(data[8:10], base.pduLength)
	}
	i := int(base.lengthIndicator)
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
	if idLength != 0 {
		return nil, errors.New("DecodePduFromBytes: ID Length not supported")
	}
	pduType := PduType(data[4])
	var err error
	switch pduType {
	case PDU_TYPE_LEVEL1_LAN_IIHP, PDU_TYPE_LEVEL2_LAN_IIHP, PDU_TYPE_P2P_IIHP:
		pdu, err = NewIihPdu(pduType)
	case PDU_TYPE_LEVEL1_LSP, PDU_TYPE_LEVEL2_LSP:
		pdu, err = NewLsPdu(pduType)
	case PDU_TYPE_LEVEL1_CSNP, PDU_TYPE_LEVEL2_CSNP, PDU_TYPE_LEVEL1_PSNP, PDU_TYPE_LEVEL2_PSNP:
		pdu, err = NewSnPdu(pduType)
	}
	if err != nil {
		return nil, err
	}
	err = pdu.DecodeFromBytes(data)
	return pdu, err
}

func (base *pduBase) SetTlv(tlv IsisTlv) error {
	tlvs := make([]IsisTlv, 0)
	for _, tlvtmp := range base.tlvs {
		if tlvtmp.TlvCode() != tlv.TlvCode() {
			tlvs = append(tlvs, tlvtmp)
		}
	}
	tlvs = append(tlvs, tlv)
	base.tlvs = tlvs
	return nil
}

func (base *pduBase) Tlv(tlvCode TlvCode) (IsisTlv, error) {
	for _, tlv := range base.tlvs {
		if tlv.TlvCode() == tlvCode {
			return tlv, nil
		}
	}
	return nil, nil
}

func (base *pduBase) AddTlv(tlv IsisTlv) error {
	base.tlvs = append(base.tlvs, tlv)
	return nil
}

func (base *pduBase) Tlvs(tlvCode TlvCode) ([]IsisTlv, error) {
	tlvs := make([]IsisTlv, 0)
	for _, tlv := range base.tlvs {
		if tlv.TlvCode() == tlvCode {
			tlvs = append(tlvs, tlv)
		}
	}
	return tlvs, nil
}

func (base *pduBase) ClearTlvs(tlvCode TlvCode) error {
	tlvs := make([]IsisTlv, 0)
	for _, tlv := range base.tlvs {
		if tlv.TlvCode() != tlvCode {
			tlvs = append(tlvs, tlv)
		}
	}
	base.tlvs = tlvs
	return nil
}
