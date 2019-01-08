package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	log "github.com/sirupsen/logrus"
)

type LsPdu struct {
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

func NewLsPdu(pduType PduType) (*LsPdu, error) {
	var lengthIndicator uint8
	if pduType != PDU_TYPE_LEVEL1_LSP &&
		pduType != PDU_TYPE_LEVEL2_LSP {
		return nil, errors.New("NewLsPdu: pduType invalid")
	}
	lengthIndicator = 21 + SYSTEM_ID_LENGTH
	ls := LsPdu{
		base: pduBase{
			lengthIndicator: lengthIndicator,
			pduType:         pduType,
		},
	}
	ls.base.init()
	ls.lspId = make([]byte, 0)
	return &ls, nil
}

func (ls *LsPdu) PduType() PduType {
	return ls.base.pduType
}

func (ls *LsPdu) String() string {
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

func (ls *LsPdu) DecodeFromBytes(data []byte) error {
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

func (ls *LsPdu) Serialize() ([]byte, error) {
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

func (ls *LsPdu) BaseValid() bool {
	return ls.base.valid()
}

/*
func (ls *LsPdu) SetChecksum() error {
	var csum uint32
	ls.Checksum = 0
	data, err := ls.Serialize()
	if err != nil {
		return errors.New("checksum error")
	}
	log.Debugf("%x", data)
	for i := 12; i < len(data)-1; i += 2 {
		csum += uint32(data[i]) << 8
		csum += uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		csum += uint32(data[len(data)-1]) << 8
	}
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	ls.Checksum = ^uint16(csum)
	return nil
}
*/

func (ls *LsPdu) SetChecksum() error {
	ls.Checksum = 0
	data, err := ls.Serialize()
	if err != nil {
		return errors.New("checksum error")
	}
	log.Debugf("%x", data)
	len := len(data) - 12
	left := len
	//p := &data[12]
	di := 12
	c0 := 0
	c1 := 0
	for left != 0 {
		tmplen := left
		if tmplen > 4102 {
			tmplen = 4102
		}
		for i := 0; i < tmplen; i++ {
			c0 = c0 + int(data[di])
			c1 += c0
			//p += *byte(1)
			di++
		}
		c0 = c0 % 255
		c1 = c1 % 255
		left -= tmplen
	}
	x := int((len-12-1)*c0-c1) % 255
	if x <= 0 {
		x += 255
	}
	y := 510 - c0 - x
	if y > 255 {
		y -= 255
	}
	csum := [2]byte{byte(x), byte(y)}
	ls.Checksum = binary.BigEndian.Uint16(csum[0:2])
	return nil
}

func (ls *LsPdu) LspId() []byte {
	lspId := make([]byte, len(ls.lspId))
	copy(lspId, ls.lspId)
	return lspId
}

func (ls *LsPdu) SetLspId(lspId []byte) error {
	if len(lspId) != LSP_ID_LENGTH {
		return errors.New("LsPdu.SetLspId: LSP ID length invalid")
	}
	lidtmp := make([]byte, LSP_ID_LENGTH)
	copy(lidtmp, lspId)
	ls.lspId = lidtmp
	return nil
}

func (ls *LsPdu) SetAreaAddressesTlv(tlv *areaAddressesTlv) error {
	return ls.base.SetTlv(tlv)
}

func (ls *LsPdu) AreaAddressesTlv() (*areaAddressesTlv, error) {
	tlvtmp, err := ls.base.Tlv(TLV_CODE_AREA_ADDRESSES)
	if tlv, ok := tlvtmp.(*areaAddressesTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (ls *LsPdu) ClearAreaAddressesTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_AREA_ADDRESSES)
}

func (ls *LsPdu) AddIsNeighboursLspTlv(tlv *isNeighboursLspTlv) error {
	return ls.base.AddTlv(tlv)
}

func (ls *LsPdu) IsNeighboursLspTlvs() ([]*isNeighboursLspTlv, error) {
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

func (ls *LsPdu) ClearIsNeighboursLspTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_IS_NEIGHBOURS_LSP)
}

func (ls *LsPdu) SetPartitionDesignatedL2IsTlv(tlv *partitionDesignatedL2IsTlv) error {
	return ls.base.SetTlv(tlv)
}

func (ls *LsPdu) PartitionDesignatedL2IsTlv() (*partitionDesignatedL2IsTlv, error) {
	tlvtmp, err := ls.base.Tlv(TLV_CODE_PARTITION_DESIGNATED_L2_IS)
	if tlv, ok := tlvtmp.(*partitionDesignatedL2IsTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (ls *LsPdu) ClearPartitionDesignatedL2IsTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_PARTITION_DESIGNATED_L2_IS)
}

func (ls *LsPdu) SetAuthInfoTlv(tlv *authInfoTlv) error {
	return ls.base.SetTlv(tlv)
}

func (ls *LsPdu) AuthInfoTlv() (*authInfoTlv, error) {
	tlvtmp, err := ls.base.Tlv(TLV_CODE_AUTH_INFO)
	if tlv, ok := tlvtmp.(*authInfoTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (ls *LsPdu) ClearAuthInfoTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_AUTH_INFO)
}

func (ls *LsPdu) AddIpInternalReachInfoTlv(tlv *ipInternalReachInfoTlv) error {
	return ls.base.AddTlv(tlv)
}

func (ls *LsPdu) IpInternalReachInfoTlvs() ([]*ipInternalReachInfoTlv, error) {
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

func (ls *LsPdu) ClearIpInternalReachInfoTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_IP_INTERNAL_REACH_INFO)
}

func (ls *LsPdu) SetProtocolsSupportedTlv(tlv *protocolsSupportedTlv) error {
	return ls.base.SetTlv(tlv)
}

func (ls *LsPdu) ProtocolsSupportedTlv() (*protocolsSupportedTlv, error) {
	tlvtmp, err := ls.base.Tlv(TLV_CODE_PROTOCOLS_SUPPORTED)
	if tlv, ok := tlvtmp.(*protocolsSupportedTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (ls *LsPdu) ClearProtocolsSupportedTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_PROTOCOLS_SUPPORTED)
}

func (ls *LsPdu) AddIpExternalReachInfoTlv(tlv *ipExternalReachInfoTlv) error {
	return ls.base.AddTlv(tlv)
}

func (ls *LsPdu) IpExternalReachInfoTlvs() ([]*ipExternalReachInfoTlv, error) {
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

func (ls *LsPdu) ClearIpExternalReachInfoTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_IP_EXTERNAL_REACH_INFO)
}

func (ls *LsPdu) AddInterDomainRoutingProtoInfoTlv(tlv *interDomainRoutingProtoInfoTlv) error {
	return ls.base.AddTlv(tlv)
}

func (ls *LsPdu) InterDomainRoutingProtoInfoTlvs() ([]*interDomainRoutingProtoInfoTlv, error) {
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

func (ls *LsPdu) ClearInterDomainRoutingProtoInfoTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_INTER_DOMAIN_ROUTING_PROTO_INFO)
}

func (ls *LsPdu) SetIpInterfaceAddressTlv(tlv *ipInterfaceAddressTlv) error {
	return ls.base.SetTlv(tlv)
}

func (ls *LsPdu) IpInterfaceAddressTlv() (*ipInterfaceAddressTlv, error) {
	tlvtmp, err := ls.base.Tlv(TLV_CODE_IP_INTERFACE_ADDRESS)
	if tlv, ok := tlvtmp.(*ipInterfaceAddressTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (ls *LsPdu) ClearIpInterfaceAddressTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_IP_INTERFACE_ADDRESS)
}

func (ls *LsPdu) SetDynamicHostnameTlv(tlv *dynamicHostnameTlv) error {
	return ls.base.SetTlv(tlv)
}

func (ls *LsPdu) DynamicHostnameTlv() (*dynamicHostnameTlv, error) {
	tlvtmp, err := ls.base.Tlv(TLV_CODE_DYNAMIC_HOSTNAME)
	if tlv, ok := tlvtmp.(*dynamicHostnameTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (ls *LsPdu) ClearDynamicHostnameTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_DYNAMIC_HOSTNAME)
}

func (ls *LsPdu) AddExtendedIsReachabilityTlv(tlv *extendedIsReachabilityTlv) error {
	return ls.base.AddTlv(tlv)
}

func (ls *LsPdu) ExtendedIsReachabilityTlvs() ([]*extendedIsReachabilityTlv, error) {
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

func (ls *LsPdu) ClearExtendedIsReachabilityTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_EXTENDED_IS_REACHABILITY)
}

func (ls *LsPdu) SetTrafficEngineeringRouterIdTlv(tlv *trafficEngineeringRouterIdTlv) error {
	return ls.base.SetTlv(tlv)
}

func (ls *LsPdu) TrafficEngineeringRouterIdTlv() (*trafficEngineeringRouterIdTlv, error) {
	tlvtmp, err := ls.base.Tlv(TLV_CODE_TRAFFIC_ENGINEERING_ROUTER_ID)
	if tlv, ok := tlvtmp.(*trafficEngineeringRouterIdTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (ls *LsPdu) ClearTrafficEngineeringRouterIdTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_TRAFFIC_ENGINEERING_ROUTER_ID)
}

func (ls *LsPdu) AddExtendedIpReachabilityTlv(tlv *extendedIpReachabilityTlv) error {
	return ls.base.AddTlv(tlv)
}

func (ls *LsPdu) ExtendedIpReachabilityTlvs() ([]*extendedIpReachabilityTlv, error) {
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

func (ls *LsPdu) ClearExtendedIpReachabilityTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_EXTENDED_IP_REACHABILITY)
}

func (ls *LsPdu) AddIpv6ReachabilityTlv(tlv *ipv6ReachabilityTlv) error {
	return ls.base.AddTlv(tlv)
}

func (ls *LsPdu) Ipv6ReachabilityTlvs() ([]*ipv6ReachabilityTlv, error) {
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

func (ls *LsPdu) ClearIpv6ReachabilityTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_IPV6_REACHABILITY)
}

func (ls *LsPdu) SetIpv6InterfaceAddressTlv(tlv *ipv6InterfaceAddressTlv) error {
	return ls.base.SetTlv(tlv)
}

func (ls *LsPdu) Ipv6InterfaceAddressTlv() (*ipv6InterfaceAddressTlv, error) {
	tlvtmp, err := ls.base.Tlv(TLV_CODE_IPV6_INTERFACE_ADDRESS)
	if tlv, ok := tlvtmp.(*ipv6InterfaceAddressTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (ls *LsPdu) ClearIpv6InterfaceAddressTlvs() error {
	return ls.base.ClearTlvs(TLV_CODE_IPV6_INTERFACE_ADDRESS)
}
