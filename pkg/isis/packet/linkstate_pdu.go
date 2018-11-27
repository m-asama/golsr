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

func (ls *lsPdu) PduType() PduType {
	return ls.base.pduType
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

func (ls *lsPdu) SetAreaAddressesTlv(tlv *areaAddressesTlv) error {
	return ls.base.SetTlv(tlv)
}

func (ls *lsPdu) AreaAddressesTlv() (*areaAddressesTlv, error) {
	tlvtmp, err := ls.base.Tlv(TLV_CODE_AREA_ADDRESSES)
	if tlv, ok := tlvtmp.(*areaAddressesTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (ls *lsPdu) ClearAreaAddressesTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_AREA_ADDRESSES)
}

func (ls *lsPdu) AddIsNeighboursLspTlv(tlv *isNeighboursLspTlv) error {
	return ls.base.AddTlv(tlv)
}

func (ls *lsPdu) IsNeighboursLspTlvs() ([]*isNeighboursLspTlv, error) {
	tlvs := make([]*isNeighboursLspTlv, 0)
	tlvstmp, err := ls.base.Tlvs(TLV_CODE_IS_NEIGHBOURS_LSP)
	if err != nil {
		return nil, err
	}
	for _, tlvtmp := range tlvstmp {
		if tlv, ok := tlvtmp.(*isNeighboursLspTlv); ok {
			tlvs = append(tlvs, tlv)
		}
	}
	return tlvs, nil
}

func (ls *lsPdu) ClearIsNeighboursLspTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_IS_NEIGHBOURS_LSP)
}

func (ls *lsPdu) SetPartitionDesignatedL2IsTlv(tlv *partitionDesignatedL2IsTlv) error {
	return ls.base.SetTlv(tlv)
}

func (ls *lsPdu) PartitionDesignatedL2IsTlv() (*partitionDesignatedL2IsTlv, error) {
	tlvtmp, err := ls.base.Tlv(TLV_CODE_PARTITION_DESIGNATED_L2_IS)
	if tlv, ok := tlvtmp.(*partitionDesignatedL2IsTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (ls *lsPdu) ClearPartitionDesignatedL2IsTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_PARTITION_DESIGNATED_L2_IS)
}

func (ls *lsPdu) SetAuthInfoTlv(tlv *authInfoTlv) error {
	return ls.base.SetTlv(tlv)
}

func (ls *lsPdu) AuthInfoTlv() (*authInfoTlv, error) {
	tlvtmp, err := ls.base.Tlv(TLV_CODE_AUTH_INFO)
	if tlv, ok := tlvtmp.(*authInfoTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (ls *lsPdu) ClearAuthInfoTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_AUTH_INFO)
}

func (ls *lsPdu) AddIpInternalReachInfoTlv(tlv *ipInternalReachInfoTlv) error {
	return ls.base.AddTlv(tlv)
}

func (ls *lsPdu) IpInternalReachInfoTlvs() ([]*ipInternalReachInfoTlv, error) {
	tlvs := make([]*ipInternalReachInfoTlv, 0)
	tlvstmp, err := ls.base.Tlvs(TLV_CODE_IP_INTERNAL_REACH_INFO)
	if err != nil {
		return nil, err
	}
	for _, tlvtmp := range tlvstmp {
		if tlv, ok := tlvtmp.(*ipInternalReachInfoTlv); ok {
			tlvs = append(tlvs, tlv)
		}
	}
	return tlvs, nil
}

func (ls *lsPdu) ClearIpInternalReachInfoTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_IP_INTERNAL_REACH_INFO)
}

func (ls *lsPdu) SetProtocolsSupportedTlv(tlv *protocolsSupportedTlv) error {
	return ls.base.SetTlv(tlv)
}

func (ls *lsPdu) ProtocolsSupportedTlv() (*protocolsSupportedTlv, error) {
	tlvtmp, err := ls.base.Tlv(TLV_CODE_PROTOCOLS_SUPPORTED)
	if tlv, ok := tlvtmp.(*protocolsSupportedTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (ls *lsPdu) ClearProtocolsSupportedTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_PROTOCOLS_SUPPORTED)
}

func (ls *lsPdu) AddIpExternalReachInfoTlv(tlv *ipExternalReachInfoTlv) error {
	return ls.base.AddTlv(tlv)
}

func (ls *lsPdu) IpExternalReachInfoTlvs() ([]*ipExternalReachInfoTlv, error) {
	tlvs := make([]*ipExternalReachInfoTlv, 0)
	tlvstmp, err := ls.base.Tlvs(TLV_CODE_IP_EXTERNAL_REACH_INFO)
	if err != nil {
		return nil, err
	}
	for _, tlvtmp := range tlvstmp {
		if tlv, ok := tlvtmp.(*ipExternalReachInfoTlv); ok {
			tlvs = append(tlvs, tlv)
		}
	}
	return tlvs, nil
}

func (ls *lsPdu) ClearIpExternalReachInfoTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_IP_EXTERNAL_REACH_INFO)
}

func (ls *lsPdu) AddInterDomainRoutingProtoInfoTlv(tlv *interDomainRoutingProtoInfoTlv) error {
	return ls.base.AddTlv(tlv)
}

func (ls *lsPdu) InterDomainRoutingProtoInfoTlvs() ([]*interDomainRoutingProtoInfoTlv, error) {
	tlvs := make([]*interDomainRoutingProtoInfoTlv, 0)
	tlvstmp, err := ls.base.Tlvs(TLV_CODE_INTER_DOMAIN_ROUTING_PROTO_INFO)
	if err != nil {
		return nil, err
	}
	for _, tlvtmp := range tlvstmp {
		if tlv, ok := tlvtmp.(*interDomainRoutingProtoInfoTlv); ok {
			tlvs = append(tlvs, tlv)
		}
	}
	return tlvs, nil
}

func (ls *lsPdu) ClearInterDomainRoutingProtoInfoTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_INTER_DOMAIN_ROUTING_PROTO_INFO)
}

func (ls *lsPdu) SetIpInterfaceAddressTlv(tlv *ipInterfaceAddressTlv) error {
	return ls.base.SetTlv(tlv)
}

func (ls *lsPdu) IpInterfaceAddressTlv() (*ipInterfaceAddressTlv, error) {
	tlvtmp, err := ls.base.Tlv(TLV_CODE_IP_INTERFACE_ADDRESS)
	if tlv, ok := tlvtmp.(*ipInterfaceAddressTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (ls *lsPdu) ClearIpInterfaceAddressTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_IP_INTERFACE_ADDRESS)
}

func (ls *lsPdu) SetDynamicHostnameTlv(tlv *dynamicHostnameTlv) error {
	return ls.base.SetTlv(tlv)
}

func (ls *lsPdu) DynamicHostnameTlv() (*dynamicHostnameTlv, error) {
	tlvtmp, err := ls.base.Tlv(TLV_CODE_DYNAMIC_HOSTNAME)
	if tlv, ok := tlvtmp.(*dynamicHostnameTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (ls *lsPdu) ClearDynamicHostnameTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_DYNAMIC_HOSTNAME)
}

func (ls *lsPdu) AddExtendedIsReachabilityTlv(tlv *extendedIsReachabilityTlv) error {
	return ls.base.AddTlv(tlv)
}

func (ls *lsPdu) ExtendedIsReachabilityTlvs() ([]*extendedIsReachabilityTlv, error) {
	tlvs := make([]*extendedIsReachabilityTlv, 0)
	tlvstmp, err := ls.base.Tlvs(TLV_CODE_EXTENDED_IS_REACHABILITY)
	if err != nil {
		return nil, err
	}
	for _, tlvtmp := range tlvstmp {
		if tlv, ok := tlvtmp.(*extendedIsReachabilityTlv); ok {
			tlvs = append(tlvs, tlv)
		}
	}
	return tlvs, nil
}

func (ls *lsPdu) ClearExtendedIsReachabilityTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_EXTENDED_IS_REACHABILITY)
}

func (ls *lsPdu) SetTrafficEngineeringRouterIdTlv(tlv *trafficEngineeringRouterIdTlv) error {
	return ls.base.SetTlv(tlv)
}

func (ls *lsPdu) TrafficEngineeringRouterIdTlv() (*trafficEngineeringRouterIdTlv, error) {
	tlvtmp, err := ls.base.Tlv(TLV_CODE_TRAFFIC_ENGINEERING_ROUTER_ID)
	if tlv, ok := tlvtmp.(*trafficEngineeringRouterIdTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (ls *lsPdu) ClearTrafficEngineeringRouterIdTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_TRAFFIC_ENGINEERING_ROUTER_ID)
}

func (ls *lsPdu) AddExtendedIpReachabilityTlv(tlv *extendedIpReachabilityTlv) error {
	return ls.base.AddTlv(tlv)
}

func (ls *lsPdu) ExtendedIpReachabilityTlvs() ([]*extendedIpReachabilityTlv, error) {
	tlvs := make([]*extendedIpReachabilityTlv, 0)
	tlvstmp, err := ls.base.Tlvs(TLV_CODE_EXTENDED_IP_REACHABILITY)
	if err != nil {
		return nil, err
	}
	for _, tlvtmp := range tlvstmp {
		if tlv, ok := tlvtmp.(*extendedIpReachabilityTlv); ok {
			tlvs = append(tlvs, tlv)
		}
	}
	return tlvs, nil
}

func (ls *lsPdu) ClearExtendedIpReachabilityTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_EXTENDED_IP_REACHABILITY)
}

func (ls *lsPdu) AddIpv6ReachabilityTlv(tlv *ipv6ReachabilityTlv) error {
	return ls.base.AddTlv(tlv)
}

func (ls *lsPdu) Ipv6ReachabilityTlvs() ([]*ipv6ReachabilityTlv, error) {
	tlvs := make([]*ipv6ReachabilityTlv, 0)
	tlvstmp, err := ls.base.Tlvs(TLV_CODE_IPV6_REACHABILITY)
	if err != nil {
		return nil, err
	}
	for _, tlvtmp := range tlvstmp {
		if tlv, ok := tlvtmp.(*ipv6ReachabilityTlv); ok {
			tlvs = append(tlvs, tlv)
		}
	}
	return tlvs, nil
}

func (ls *lsPdu) ClearIpv6ReachabilityTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_IPV6_REACHABILITY)
}

func (ls *lsPdu) SetIpv6InterfaceAddressTlv(tlv *ipv6InterfaceAddressTlv) error {
	return ls.base.SetTlv(tlv)
}

func (ls *lsPdu) Ipv6InterfaceAddressTlv() (*ipv6InterfaceAddressTlv, error) {
	tlvtmp, err := ls.base.Tlv(TLV_CODE_IPV6_INTERFACE_ADDRESS)
	if tlv, ok := tlvtmp.(*ipv6InterfaceAddressTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (ls *lsPdu) ClearIpv6InterfaceAddressTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_IPV6_INTERFACE_ADDRESS)
}
