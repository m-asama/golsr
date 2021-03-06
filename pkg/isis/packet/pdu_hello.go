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

type IihPdu struct {
	base pduBase

	CircuitType    CircuitType
	sourceId       [SYSTEM_ID_LENGTH]byte
	HoldingTime    uint16
	Priority       uint8                     // LAN
	lanId          [NEIGHBOUR_ID_LENGTH]byte // LAN
	LocalCircuitId uint8                     // P2P
}

func NewIihPdu(pduType PduType) (*IihPdu, error) {
	if pduType != PDU_TYPE_LEVEL1_LAN_IIHP &&
		pduType != PDU_TYPE_LEVEL2_LAN_IIHP &&
		pduType != PDU_TYPE_P2P_IIHP {
		return nil, errors.New("NewIihPdu: pduType invalid")
	}
	var lengthIndicator uint8
	switch pduType {
	case PDU_TYPE_LEVEL1_LAN_IIHP, PDU_TYPE_LEVEL2_LAN_IIHP:
		lengthIndicator = 14 + SYSTEM_ID_LENGTH + NEIGHBOUR_ID_LENGTH
	case PDU_TYPE_P2P_IIHP:
		lengthIndicator = 14 + SYSTEM_ID_LENGTH
	}
	iih := IihPdu{
		base: pduBase{
			lengthIndicator: lengthIndicator,
			pduType:         pduType,
		},
	}
	iih.base.init()
	return &iih, nil
}

func (iih *IihPdu) PduType() PduType {
	return iih.base.pduType
}

func (iih *IihPdu) String() string {
	var b bytes.Buffer
	b.WriteString(iih.base.StringFixed())
	fmt.Fprintf(&b, "CircuitType                     %s\n", iih.CircuitType.String())
	fmt.Fprintf(&b, "sourceId                        ")
	for t := range iih.sourceId {
		fmt.Fprintf(&b, "%02x", t)
	}
	fmt.Fprintf(&b, "\n")
	fmt.Fprintf(&b, "HoldingTime                     %d\n", iih.HoldingTime)
	if iih.base.pduType == PDU_TYPE_LEVEL1_LAN_IIHP ||
		iih.base.pduType == PDU_TYPE_LEVEL2_LAN_IIHP {
		fmt.Fprintf(&b, "Priority                        %d\n", iih.Priority)
		fmt.Fprintf(&b, "lanId                           ")
		for t := range iih.lanId {
			fmt.Fprintf(&b, "%02x", t)
		}
		fmt.Fprintf(&b, "\n")
	}
	if iih.base.pduType == PDU_TYPE_P2P_IIHP {
		fmt.Fprintf(&b, "LocalCircuitId                  0x%02x\n", iih.LocalCircuitId)
	}
	b.WriteString(iih.base.StringTlv())
	return b.String()
}

func (iih *IihPdu) DecodeFromBytes(data []byte) error {
	err := iih.base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	//
	// CircuitType
	iih.CircuitType = CircuitType(data[8])
	//
	// SourceId
	copy(iih.sourceId[0:SYSTEM_ID_LENGTH], data[9:9+SYSTEM_ID_LENGTH])
	//
	// HoldingTime
	iih.HoldingTime = binary.BigEndian.Uint16(data[9+SYSTEM_ID_LENGTH : 11+SYSTEM_ID_LENGTH])
	switch iih.base.pduType {
	case PDU_TYPE_LEVEL1_LAN_IIHP, PDU_TYPE_LEVEL2_LAN_IIHP:
		//
		// Priority
		iih.Priority = data[13+SYSTEM_ID_LENGTH]
		//
		// LanId
		copy(iih.lanId[0:NEIGHBOUR_ID_LENGTH],
			data[14+SYSTEM_ID_LENGTH:14+SYSTEM_ID_LENGTH+NEIGHBOUR_ID_LENGTH])
	case PDU_TYPE_P2P_IIHP:
		//
		// LocalCircuitId
		iih.LocalCircuitId = data[13+SYSTEM_ID_LENGTH]
	default:
		return errors.New("IihPdu.DecodeFromBytes: pduType invalid")
	}
	return nil
}

func (iih *IihPdu) Serialize() ([]byte, error) {
	data, err := iih.base.Serialize()
	if err != nil {
		return data, err
	}
	//
	// CircuitType
	data[8] = uint8(iih.CircuitType)
	//
	// SourceId
	copy(data[9:9+SYSTEM_ID_LENGTH], iih.sourceId[0:SYSTEM_ID_LENGTH])
	//
	// HoldingTime
	binary.BigEndian.PutUint16(data[9+SYSTEM_ID_LENGTH:11+SYSTEM_ID_LENGTH], iih.HoldingTime)
	switch iih.base.pduType {
	case PDU_TYPE_LEVEL1_LAN_IIHP, PDU_TYPE_LEVEL2_LAN_IIHP:
		//
		// Priority
		data[13+SYSTEM_ID_LENGTH] = iih.Priority
		//
		// LanId
		copy(data[14+SYSTEM_ID_LENGTH:14+SYSTEM_ID_LENGTH+NEIGHBOUR_ID_LENGTH],
			iih.lanId[0:NEIGHBOUR_ID_LENGTH])
	case PDU_TYPE_P2P_IIHP:
		//
		// LocalCircuitId
		data[13+SYSTEM_ID_LENGTH] = iih.LocalCircuitId
	default:
		return nil, errors.New("IihPdu.Serialize: pduType invalid")
	}
	return data, nil
}

func (iih *IihPdu) BaseValid() bool {
	return iih.base.valid()
}

func (iih *IihPdu) SourceId() [SYSTEM_ID_LENGTH]byte {
	return iih.sourceId
}

func (iih *IihPdu) SetSourceId(sourceId [SYSTEM_ID_LENGTH]byte) error {
	iih.sourceId = sourceId
	return nil
}

func (iih *IihPdu) LanId() [NEIGHBOUR_ID_LENGTH]byte {
	return iih.lanId
}

func (iih *IihPdu) SetLanId(lanId [NEIGHBOUR_ID_LENGTH]byte) error {
	iih.lanId = lanId
	return nil
}

func (iih *IihPdu) SetAreaAddressesTlv(tlv *areaAddressesTlv) error {
	return iih.base.SetTlv(tlv)
}

func (iih *IihPdu) AreaAddressesTlv() (*areaAddressesTlv, error) {
	tlvtmp, err := iih.base.Tlv(TLV_CODE_AREA_ADDRESSES)
	if tlv, ok := tlvtmp.(*areaAddressesTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (iih *IihPdu) ClearAreaAddressesTlvs() error {
	return iih.base.ClearTlvs(TLV_CODE_AREA_ADDRESSES)
}

func (iih *IihPdu) AddIsNeighboursHelloTlv(tlv *isNeighboursHelloTlv) error {
	return iih.base.AddTlv(tlv)
}

func (iih *IihPdu) IsNeighboursHelloTlvs() ([]*isNeighboursHelloTlv, error) {
	tlvs := make([]*isNeighboursHelloTlv, 0)
	tlvstmp, err := iih.base.Tlvs(TLV_CODE_IS_NEIGHBOURS_HELLO)
	if err != nil {
		return nil, err
	}
	for _, tlvtmp := range tlvstmp {
		if tlv, ok := tlvtmp.(*isNeighboursHelloTlv); ok {
			tlvs = append(tlvs, tlv)
		}
	}
	return tlvs, nil
}

func (iih *IihPdu) ClearIsNeighboursHelloTlvs() error {
	return iih.base.ClearTlvs(TLV_CODE_IS_NEIGHBOURS_HELLO)
}

func (iih *IihPdu) AddPaddingTlv(tlv *paddingTlv) error {
	return iih.base.AddTlv(tlv)
}

func (iih *IihPdu) ClearAddPaddingTlvs() error {
	return iih.base.ClearTlvs(TLV_CODE_PADDING)
}

func (iih *IihPdu) SetAuthInfoTlv(tlv *authInfoTlv) error {
	return iih.base.SetTlv(tlv)
}

func (iih *IihPdu) AuthInfoTlv() (*authInfoTlv, error) {
	tlvtmp, err := iih.base.Tlv(TLV_CODE_AUTH_INFO)
	if tlv, ok := tlvtmp.(*authInfoTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (iih *IihPdu) ClearAuthInfoTlvs() error {
	return iih.base.ClearTlvs(TLV_CODE_AUTH_INFO)
}

func (iih *IihPdu) SetProtocolsSupportedTlv(tlv *protocolsSupportedTlv) error {
	return iih.base.SetTlv(tlv)
}

func (iih *IihPdu) ProtocolsSupportedTlv() (*protocolsSupportedTlv, error) {
	tlvtmp, err := iih.base.Tlv(TLV_CODE_PROTOCOLS_SUPPORTED)
	if tlv, ok := tlvtmp.(*protocolsSupportedTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (iih *IihPdu) ClearProtocolsSupportedTlvs() error {
	return iih.base.ClearTlvs(TLV_CODE_PROTOCOLS_SUPPORTED)
}

func (iih *IihPdu) SetIpInterfaceAddressTlv(tlv *ipInterfaceAddressTlv) error {
	return iih.base.SetTlv(tlv)
}

func (iih *IihPdu) IpInterfaceAddressTlv() (*ipInterfaceAddressTlv, error) {
	tlvtmp, err := iih.base.Tlv(TLV_CODE_IP_INTERFACE_ADDRESS)
	if tlv, ok := tlvtmp.(*ipInterfaceAddressTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (iih *IihPdu) ClearIpInterfaceAddressTlvs() error {
	return iih.base.ClearTlvs(TLV_CODE_IP_INTERFACE_ADDRESS)
}

func (iih *IihPdu) SetP2p3wayAdjacencyTlv(tlv *p2p3wayAdjacencyTlv) error {
	return iih.base.SetTlv(tlv)
}

func (iih *IihPdu) P2p3wayAdjacencyTlv() (*p2p3wayAdjacencyTlv, error) {
	tlvtmp, err := iih.base.Tlv(TLV_CODE_P2P_3WAY_ADJ)
	if tlv, ok := tlvtmp.(*p2p3wayAdjacencyTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (iih *IihPdu) ClearP2p3wayAdjacencyTlvs() error {
	return iih.base.ClearTlvs(TLV_CODE_P2P_3WAY_ADJ)
}

func (iih *IihPdu) SetIpv6InterfaceAddressTlv(tlv *ipv6InterfaceAddressTlv) error {
	return iih.base.SetTlv(tlv)
}

func (iih *IihPdu) Ipv6InterfaceAddressTlv() (*ipv6InterfaceAddressTlv, error) {
	tlvtmp, err := iih.base.Tlv(TLV_CODE_IPV6_INTERFACE_ADDRESS)
	if tlv, ok := tlvtmp.(*ipv6InterfaceAddressTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (iih *IihPdu) ClearIpv6InterfaceAddressTlvs() error {
	return iih.base.ClearTlvs(TLV_CODE_IPV6_INTERFACE_ADDRESS)
}
