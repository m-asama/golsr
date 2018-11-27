package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type iihPdu struct {
	base pduBase

	CircuitType    CircuitType
	sourceId       []byte
	HoldingTime    uint16
	Priority       uint8  // LAN
	lanId          []byte // LAN
	LocalCircuitId uint8  // P2P
}

func NewIihPdu(pduType PduType) (*iihPdu, error) {
	if pduType != PDU_TYPE_LEVEL1_LAN_IIHP &&
		pduType != PDU_TYPE_LEVEL2_LAN_IIHP &&
		pduType != PDU_TYPE_P2P_IIHP {
		return nil, errors.New("NewIihPdu: pduType invalid")
	}
	var lengthIndicator uint8
	switch pduType {
	case PDU_TYPE_LEVEL1_LAN_IIHP, PDU_TYPE_LEVEL2_LAN_IIHP:
		lengthIndicator = 15 + SYSTEM_ID_LENGTH*2
	case PDU_TYPE_P2P_IIHP:
		lengthIndicator = 14 + SYSTEM_ID_LENGTH
	}
	iih := iihPdu{
		base: pduBase{
			lengthIndicator: lengthIndicator,
			pduType:         pduType,
		},
	}
	iih.base.init()
	iih.sourceId = make([]byte, 0)
	iih.lanId = make([]byte, 0)
	return &iih, nil
}

func (iih *iihPdu) PduType() PduType {
	return iih.base.pduType
}

func (iih *iihPdu) String() string {
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

func (iih *iihPdu) DecodeFromBytes(data []byte) error {
	err := iih.base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	//
	// CircuitType
	iih.CircuitType = CircuitType(data[8])
	//
	// SourceId
	sourceId := make([]byte, iih.base.idLength)
	copy(sourceId, data[9:9+iih.base.idLength])
	iih.sourceId = sourceId
	//
	// HoldingTime
	iih.HoldingTime = binary.BigEndian.Uint16(data[9+iih.base.idLength : 11+iih.base.idLength])
	switch iih.base.pduType {
	case PDU_TYPE_LEVEL1_LAN_IIHP, PDU_TYPE_LEVEL2_LAN_IIHP:
		//
		// Priority
		iih.Priority = data[13+iih.base.idLength]
		//
		// LanId
		lanId := make([]byte, iih.base.idLength+1)
		copy(lanId, data[14+iih.base.idLength:15+iih.base.idLength*2])
		iih.lanId = lanId
	case PDU_TYPE_P2P_IIHP:
		//
		// LocalCircuitId
		iih.LocalCircuitId = data[13+iih.base.idLength]
	default:
		return errors.New("iihPdu.DecodeFromBytes: pduType invalid")
	}
	return nil
}

func (iih *iihPdu) Serialize() ([]byte, error) {
	data, err := iih.base.Serialize()
	if err != nil {
		return data, err
	}
	//
	// CircuitType
	data[8] = uint8(iih.CircuitType)
	//
	// SourceId
	copy(data[9:9+iih.base.idLength], iih.sourceId)
	//
	// HoldingTime
	binary.BigEndian.PutUint16(data[9+iih.base.idLength:11+iih.base.idLength], iih.HoldingTime)
	switch iih.base.pduType {
	case PDU_TYPE_LEVEL1_LAN_IIHP, PDU_TYPE_LEVEL2_LAN_IIHP:
		//
		// Priority
		data[13+iih.base.idLength] = iih.Priority
		//
		// LanId
		copy(data[14+iih.base.idLength:15+iih.base.idLength*2], iih.lanId)
	case PDU_TYPE_P2P_IIHP:
		//
		// LocalCircuitId
		data[13+iih.base.idLength] = iih.LocalCircuitId
	default:
		return nil, errors.New("iihPdu.Serialize: pduType invalid")
	}
	return data, nil
}

func (iih *iihPdu) SetAreaAddressesTlv(tlv *areaAddressesTlv) error {
	return iih.base.SetTlv(tlv)
}

func (iih *iihPdu) AreaAddressesTlv() (*areaAddressesTlv, error) {
	tlvtmp, err := iih.base.Tlv(TLV_CODE_AREA_ADDRESSES)
	if tlv, ok := tlvtmp.(*areaAddressesTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (iih *iihPdu) ClearAreaAddressesTlvs() error {
	return iih.base.ClearTlvs(TLV_CODE_AREA_ADDRESSES)
}

func (iih *iihPdu) AddIsNeighboursHelloTlv(tlv *isNeighboursHelloTlv) error {
	return iih.base.AddTlv(tlv)
}

func (iih *iihPdu) IsNeighboursHelloTlvs() ([]*isNeighboursHelloTlv, error) {
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

func (iih *iihPdu) ClearIsNeighboursHelloTlvs() error {
	return iih.base.ClearTlvs(TLV_CODE_IS_NEIGHBOURS_HELLO)
}

func (iih *iihPdu) AddPaddingTlv(tlv *paddingTlv) error {
	return iih.base.AddTlv(tlv)
}

func (iih *iihPdu) ClearAddPaddingTlvs() error {
	return iih.base.ClearTlvs(TLV_CODE_PADDING)
}

func (iih *iihPdu) SetAuthInfoTlv(tlv *authInfoTlv) error {
	return iih.base.SetTlv(tlv)
}

func (iih *iihPdu) AuthInfoTlv() (*authInfoTlv, error) {
	tlvtmp, err := iih.base.Tlv(TLV_CODE_AUTH_INFO)
	if tlv, ok := tlvtmp.(*authInfoTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (iih *iihPdu) ClearAuthInfoTlvs() error {
	return iih.base.ClearTlvs(TLV_CODE_AUTH_INFO)
}

func (iih *iihPdu) SetProtocolsSupportedTlv(tlv *protocolsSupportedTlv) error {
	return iih.base.SetTlv(tlv)
}

func (iih *iihPdu) ProtocolsSupportedTlv() (*protocolsSupportedTlv, error) {
	tlvtmp, err := iih.base.Tlv(TLV_CODE_PROTOCOLS_SUPPORTED)
	if tlv, ok := tlvtmp.(*protocolsSupportedTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (iih *iihPdu) ClearProtocolsSupportedTlvs() error {
	return iih.base.ClearTlvs(TLV_CODE_PROTOCOLS_SUPPORTED)
}

func (iih *iihPdu) SetIpInterfaceAddressTlv(tlv *ipInterfaceAddressTlv) error {
	return iih.base.SetTlv(tlv)
}

func (iih *iihPdu) IpInterfaceAddressTlv() (*ipInterfaceAddressTlv, error) {
	tlvtmp, err := iih.base.Tlv(TLV_CODE_IP_INTERFACE_ADDRESS)
	if tlv, ok := tlvtmp.(*ipInterfaceAddressTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (iih *iihPdu) ClearIpInterfaceAddressTlvs() error {
	return iih.base.ClearTlvs(TLV_CODE_IP_INTERFACE_ADDRESS)
}

func (iih *iihPdu) SetP2p3wayAdjacencyTlv(tlv *p2p3wayAdjacencyTlv) error {
	return iih.base.SetTlv(tlv)
}

func (iih *iihPdu) P2p3wayAdjacencyTlv() (*p2p3wayAdjacencyTlv, error) {
	tlvtmp, err := iih.base.Tlv(TLV_CODE_P2P_3WAY_ADJ)
	if tlv, ok := tlvtmp.(*p2p3wayAdjacencyTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (iih *iihPdu) ClearP2p3wayAdjacencyTlvs() error {
	return iih.base.ClearTlvs(TLV_CODE_P2P_3WAY_ADJ)
}

func (iih *iihPdu) SetIpv6InterfaceAddressTlv(tlv *ipv6InterfaceAddressTlv) error {
	return iih.base.SetTlv(tlv)
}

func (iih *iihPdu) Ipv6InterfaceAddressTlv() (*ipv6InterfaceAddressTlv, error) {
	tlvtmp, err := iih.base.Tlv(TLV_CODE_IPV6_INTERFACE_ADDRESS)
	if tlv, ok := tlvtmp.(*ipv6InterfaceAddressTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (iih *iihPdu) ClearIpv6InterfaceAddressTlvs() error {
	return iih.base.ClearTlvs(TLV_CODE_IPV6_INTERFACE_ADDRESS)
}
