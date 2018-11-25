package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

/*
	IP Internal Reachability Information
	Code - 128
	Length - a multiple of 12
	Value -
	+---+---+----------------+
	| 0 |I/E| Default Metric | 1
	+---+---+----------------+
	| S | R | Delay Metric   | 1
	+---+---+----------------+
	| S | R | Expense Metric | 1
	+---+---+----------------+
	| S | R | Error Metric   | 1
	+---+---+----------------+
	| IP Address             | 4
	+------------------------+
	| Subnet Mask            | 4
	+------------------------+
	:                        :
	:                        :
	+---+---+----------------+
	| 0 |I/E| Default Metric | 1
	+---+---+----------------+
	| S | R | Delay Metric   | 1
	+---+---+----------------+
	| S | R | Expense Metric | 1
	+---+---+----------------+
	| S | R | Error Metric   | 1
	+---+---+----------------+
	| IP Address             | 4
	+------------------------+
	| Subnet Mask            | 4
	+------------------------+
*/

type ipInternalReachInfoIpSubnet struct {
	DefaultMetric          uint8
	DefaultMetricType      MetricType
	DelayMetric            uint8
	DelayMetricSupported   bool
	ExpenseMetric          uint8
	ExpenseMetricSupported bool
	ErrorMetric            uint8
	ErrorMetricSupported   bool
	IpAddress              uint32
	SubnetMask             uint32
}

func NewIpInternalReachInfoIpSubnet() (*ipInternalReachInfoIpSubnet, error) {
	ipSubnet := ipInternalReachInfoIpSubnet{}
	return &ipSubnet, nil
}

type ipInternalReachInfoTlv struct {
	Base      tlvBase
	ipSubnets []ipInternalReachInfoIpSubnet
}

func NewIpInternalReachInfoTlv() (*ipInternalReachInfoTlv, error) {
	tlv := ipInternalReachInfoTlv{
		Base: tlvBase{
			Code: TLV_CODE_IP_INTERNAL_REACH_INFO,
		},
	}
	tlv.Base.Init()
	tlv.ipSubnets = make([]ipInternalReachInfoIpSubnet, 0)
	return &tlv, nil
}

func (tlv *ipInternalReachInfoTlv) AddIpSubnet(ipSubnet *ipInternalReachInfoIpSubnet) error {
	length := 0
	for _, istmp := range tlv.ipSubnets {
		if ipSubnet.IpAddress == istmp.IpAddress && ipSubnet.SubnetMask == istmp.SubnetMask {
			return nil
		}
		length += 12
	}
	if length+12 > 255 {
		return errors.New("IpInternalReachInfoTlv.AddIpSubnet: size over")
	}
	tlv.ipSubnets = append(tlv.ipSubnets, *ipSubnet)
	tlv.Base.Length = uint8(length + 12)
	return nil
}

func (tlv *ipInternalReachInfoTlv) RemoveIpSubnet(ipAddress, subnetMask uint32) error {
	length := 0
	ipSubnets := make([]ipInternalReachInfoIpSubnet, 0)
	for _, istmp := range tlv.ipSubnets {
		if ipAddress != istmp.IpAddress || subnetMask != istmp.SubnetMask {
			ipSubnets = append(ipSubnets, istmp)
			length += 12
		}
	}
	tlv.ipSubnets = ipSubnets
	tlv.Base.Length = uint8(length)
	return nil
}

func (tlv *ipInternalReachInfoTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.Base.String())
	for _, istmp := range tlv.ipSubnets {
		fmt.Fprintf(&b, "    DefaultMetric       %d\n", istmp.DefaultMetric)
		fmt.Fprintf(&b, "    DefaultMetricType   %s\n", istmp.DefaultMetricType)
		fmt.Fprintf(&b, "    DelayMetric         %d\n", istmp.DelayMetric)
		fmt.Fprintf(&b, "    DelayMetricSupported %t\n", istmp.DelayMetricSupported)
		fmt.Fprintf(&b, "    ExpenseMetric       %d\n", istmp.ExpenseMetric)
		fmt.Fprintf(&b, "    ExpenseMetricSupported %t\n", istmp.ExpenseMetricSupported)
		fmt.Fprintf(&b, "    ErrorMetric         %d\n", istmp.ErrorMetric)
		fmt.Fprintf(&b, "    ErrorMetricSupported %t\n", istmp.ErrorMetricSupported)
		fmt.Fprintf(&b, "    IP Address          %08x", istmp.IpAddress)
		fmt.Fprintf(&b, "    Subnet Mask         %08x", istmp.SubnetMask)
	}
	return b.String()
}

func (tlv *ipInternalReachInfoTlv) DecodeFromBytes(data []byte) error {
	err := tlv.Base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	ipSubnets := make([]ipInternalReachInfoIpSubnet, 0)
	consumed := 0
	for i := 0; i < len(tlv.Base.Value); i += 12 {
		istmp, _ := NewIpInternalReachInfoIpSubnet()
		istmp.DefaultMetric = (tlv.Base.Value[i+0] & 0x3f)
		istmp.DefaultMetricType = MetricType(tlv.Base.Value[i+0] & 0x40)
		istmp.DelayMetric = (tlv.Base.Value[i+1] & 0x3f)
		istmp.DelayMetricSupported = ((tlv.Base.Value[i+1] & 0x80) == 0x00)
		istmp.ExpenseMetric = (tlv.Base.Value[i+2] & 0x3f)
		istmp.ExpenseMetricSupported = ((tlv.Base.Value[i+2] & 0x80) == 0x00)
		istmp.ErrorMetric = (tlv.Base.Value[i+3] & 0x3f)
		istmp.ErrorMetricSupported = ((tlv.Base.Value[i+3] & 0x80) == 0x00)
		istmp.IpAddress = binary.BigEndian.Uint32(tlv.Base.Value[i+4 : i+8])
		istmp.SubnetMask = binary.BigEndian.Uint32(tlv.Base.Value[i+8 : i+12])
		ipSubnets = append(ipSubnets, *istmp)
		consumed += 12
	}
	if consumed != len(tlv.Base.Value) {
		return errors.New("IpInternalReachInfoTlv.DecodeFromBytes: value length mismatch")
	}
	tlv.ipSubnets = ipSubnets
	return nil
}

func (tlv *ipInternalReachInfoTlv) Serialize() ([]byte, error) {
	length := 12 * len(tlv.ipSubnets)
	value := make([]byte, length)
	i := 0
	for _, istmp := range tlv.ipSubnets {
		value[i+0] = (istmp.DefaultMetric & 0x3f)
		if istmp.DefaultMetricType == METRIC_TYPE_EXTERNAL {
			value[i+0] |= 0x40
		}
		value[i+1] = (istmp.DelayMetric & 0x3f)
		if !istmp.DelayMetricSupported {
			value[i+1] |= 0x80
		}
		value[i+2] = (istmp.ExpenseMetric & 0x3f)
		if !istmp.ExpenseMetricSupported {
			value[i+2] |= 0x80
		}
		value[i+3] = (istmp.ErrorMetric & 0x3f)
		if !istmp.ErrorMetricSupported {
			value[i+3] |= 0x80
		}
		binary.BigEndian.PutUint32(value[i+4:i+8], istmp.IpAddress)
		binary.BigEndian.PutUint32(value[i+8:i+12], istmp.SubnetMask)
		i += 12
	}
	tlv.Base.Length = uint8(length)
	tlv.Base.Value = value
	data, err := tlv.Base.Serialize()
	if err != nil {
		return data, err
	}
	return data, nil
}

/*
	Protocols Supported
	Code - 129
	Length - Total length of the value field.
	Value -
	+------------------------+
	| NLPID                  | 1
	+------------------------+
	:                        :
	:                        :
	+------------------------+
	| NLPID                  | 1
	+------------------------+
*/

type protocolsSupportedTlv struct {
	Base   tlvBase
	nlpIds []NlpId
}

func NewProtocolsSupportedTlv() (*protocolsSupportedTlv, error) {
	tlv := protocolsSupportedTlv{
		Base: tlvBase{
			Code: TLV_CODE_PROTOCOLS_SUPPORTED,
		},
	}
	tlv.Base.Init()
	tlv.nlpIds = make([]NlpId, 0)
	return &tlv, nil
}

func (tlv *protocolsSupportedTlv) AddNlpId(nlpId NlpId) error {
	for _, nitmp := range tlv.nlpIds {
		if nlpId == nitmp {
			return nil
		}
	}
	length := len(tlv.nlpIds)
	if length+1 > 255 {
		return errors.New("ProtocolsSupportedTlv.AddNlpId: size over")
	}
	tlv.nlpIds = append(tlv.nlpIds, nlpId)
	tlv.Base.Length = uint8(length + 1)
	return nil
}

func (tlv *protocolsSupportedTlv) RemoveNlpId(nlpId NlpId) error {
	nlpIds := make([]NlpId, 0)
	for _, nitmp := range tlv.nlpIds {
		if nlpId != nitmp {
			nlpIds = append(nlpIds, nitmp)
		}
	}
	tlv.nlpIds = nlpIds
	tlv.Base.Length = uint8(len(tlv.nlpIds))
	return nil
}

func (tlv *protocolsSupportedTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.Base.String())
	for _, nitmp := range tlv.nlpIds {
		fmt.Fprintf(&b, "    NLP ID              %s\n", nitmp)
	}
	return b.String()
}

func (tlv *protocolsSupportedTlv) DecodeFromBytes(data []byte) error {
	err := tlv.Base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	nlpIds := make([]NlpId, 0)
	consumed := 0
	for i := 0; i < len(tlv.Base.Value); i++ {
		if i+1 > len(tlv.Base.Value) {
			return errors.New("ProtocolsSupportedTlv.DecodeFromBytes: value length overflow")
		}
		nlpIds = append(nlpIds, NlpId(tlv.Base.Value[i]))
		consumed++
	}
	if consumed != len(tlv.Base.Value) {
		return errors.New("ProtocolsSupportedTlv.DecodeFromBytes: value length mismatch")
	}
	tlv.nlpIds = nlpIds
	return nil
}

func (tlv *protocolsSupportedTlv) Serialize() ([]byte, error) {
	length := len(tlv.nlpIds)
	value := make([]byte, length)
	for i, nlpId := range tlv.nlpIds {
		value[i] = byte(nlpId)
	}
	tlv.Base.Length = uint8(length)
	tlv.Base.Value = value
	data, err := tlv.Base.Serialize()
	if err != nil {
		return data, err
	}
	return data, nil
}

/*
	IP External Reachability Information
	Code - 130
	Length - a multiple of 12.
	Value -
	+---+---+----------------+
	| 0 |I/E| Default Metric | 1
	+---+---+----------------+
	| S | R | Delay Metric   | 1
	+---+---+----------------+
	| S | R | Expense Metric | 1
	+---+---+----------------+
	| S | R | Error Metric   | 1
	+---+---+----------------+
	| IP Address             | 4
	+------------------------+
	| Subnet Mask            | 4
	+------------------------+
	:                        :
	:                        :
	+---+---+----------------+
	| 0 |I/E| Default Metric | 1
	+---+---+----------------+
	| S | R | Delay Metric   | 1
	+---+---+----------------+
	| S | R | Expense Metric | 1
	+---+---+----------------+
	| S | R | Error Metric   | 1
	+---+---+----------------+
	| IP Address             | 4
	+------------------------+
	| Subnet Mask            | 4
	+------------------------+
*/

type ipExternalReachInfoIpSubnet struct {
	DefaultMetric          uint8
	DefaultMetricType      MetricType
	DelayMetric            uint8
	DelayMetricSupported   bool
	ExpenseMetric          uint8
	ExpenseMetricSupported bool
	ErrorMetric            uint8
	ErrorMetricSupported   bool
	IpAddress              uint32
	SubnetMask             uint32
}

func NewIpExternalReachInfoIpSubnet() (*ipExternalReachInfoIpSubnet, error) {
	ipSubnet := ipExternalReachInfoIpSubnet{}
	return &ipSubnet, nil
}

type ipExternalReachInfoTlv struct {
	Base      tlvBase
	ipSubnets []ipExternalReachInfoIpSubnet
}

func NewIpExternalReachInfoTlv() (*ipExternalReachInfoTlv, error) {
	tlv := ipExternalReachInfoTlv{
		Base: tlvBase{
			Code: TLV_CODE_IP_EXTERNAL_REACH_INFO,
		},
	}
	tlv.Base.Init()
	tlv.ipSubnets = make([]ipExternalReachInfoIpSubnet, 0)
	return &tlv, nil
}

func (tlv *ipExternalReachInfoTlv) AddIpSubnet(ipSubnet *ipExternalReachInfoIpSubnet) error {
	length := 0
	for _, istmp := range tlv.ipSubnets {
		if ipSubnet.IpAddress == istmp.IpAddress && ipSubnet.SubnetMask == istmp.SubnetMask {
			return nil
		}
		length += 12
	}
	if length+12 > 255 {
		return errors.New("IpExternalReachInfoTlv.AddIpSubnet: size over")
	}
	tlv.ipSubnets = append(tlv.ipSubnets, *ipSubnet)
	tlv.Base.Length = uint8(length + 12)
	return nil
}

func (tlv *ipExternalReachInfoTlv) RemoveIpSubnet(ipAddress, subnetMask uint32) error {
	length := 0
	ipSubnets := make([]ipExternalReachInfoIpSubnet, 0)
	for _, istmp := range tlv.ipSubnets {
		if ipAddress != istmp.IpAddress || subnetMask != istmp.SubnetMask {
			ipSubnets = append(ipSubnets, istmp)
			length += 12
		}
	}
	tlv.ipSubnets = ipSubnets
	tlv.Base.Length = uint8(length)
	return nil
}

func (tlv *ipExternalReachInfoTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.Base.String())
	for _, istmp := range tlv.ipSubnets {
		fmt.Fprintf(&b, "    DefaultMetric       %d\n", istmp.DefaultMetric)
		fmt.Fprintf(&b, "    DefaultMetricType   %s\n", istmp.DefaultMetricType)
		fmt.Fprintf(&b, "    DelayMetric         %d\n", istmp.DelayMetric)
		fmt.Fprintf(&b, "    DelayMetricSupported %t\n", istmp.DelayMetricSupported)
		fmt.Fprintf(&b, "    ExpenseMetric       %d\n", istmp.ExpenseMetric)
		fmt.Fprintf(&b, "    ExpenseMetricSupported %t\n", istmp.ExpenseMetricSupported)
		fmt.Fprintf(&b, "    ErrorMetric         %d\n", istmp.ErrorMetric)
		fmt.Fprintf(&b, "    ErrorMetricSupported %t\n", istmp.ErrorMetricSupported)
		fmt.Fprintf(&b, "    IP Address          %08x", istmp.IpAddress)
		fmt.Fprintf(&b, "    Subnet Mask         %08x", istmp.SubnetMask)
	}
	return b.String()
}

func (tlv *ipExternalReachInfoTlv) DecodeFromBytes(data []byte) error {
	err := tlv.Base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	ipSubnets := make([]ipExternalReachInfoIpSubnet, 0)
	consumed := 0
	for i := 0; i < len(tlv.Base.Value); i += 12 {
		istmp, _ := NewIpExternalReachInfoIpSubnet()
		istmp.DefaultMetric = (tlv.Base.Value[i+0] & 0x3f)
		istmp.DefaultMetricType = MetricType(tlv.Base.Value[i+0] & 0x40)
		istmp.DelayMetric = (tlv.Base.Value[i+1] & 0x3f)
		istmp.DelayMetricSupported = ((tlv.Base.Value[i+1] & 0x80) == 0x00)
		istmp.ExpenseMetric = (tlv.Base.Value[i+2] & 0x3f)
		istmp.ExpenseMetricSupported = ((tlv.Base.Value[i+2] & 0x80) == 0x00)
		istmp.ErrorMetric = (tlv.Base.Value[i+3] & 0x3f)
		istmp.ErrorMetricSupported = ((tlv.Base.Value[i+3] & 0x80) == 0x00)
		istmp.IpAddress = binary.BigEndian.Uint32(tlv.Base.Value[i+4 : i+8])
		istmp.SubnetMask = binary.BigEndian.Uint32(tlv.Base.Value[i+8 : i+12])
		ipSubnets = append(ipSubnets, *istmp)
		consumed += 12
	}
	if consumed != len(tlv.Base.Value) {
		return errors.New("IpExternalReachInfoTlv.DecodeFromBytes: value length mismatch")
	}
	tlv.ipSubnets = ipSubnets
	return nil
}

func (tlv *ipExternalReachInfoTlv) Serialize() ([]byte, error) {
	length := 12 * len(tlv.ipSubnets)
	value := make([]byte, length)
	i := 0
	for _, istmp := range tlv.ipSubnets {
		value[i+0] = (istmp.DefaultMetric & 0x3f)
		if istmp.DefaultMetricType == METRIC_TYPE_EXTERNAL {
			value[i+0] |= 0x40
		}
		value[i+1] = (istmp.DelayMetric & 0x3f)
		if !istmp.DelayMetricSupported {
			value[i+1] |= 0x80
		}
		value[i+2] = (istmp.ExpenseMetric & 0x3f)
		if !istmp.ExpenseMetricSupported {
			value[i+2] |= 0x80
		}
		value[i+3] = (istmp.ErrorMetric & 0x3f)
		if !istmp.ErrorMetricSupported {
			value[i+3] |= 0x80
		}
		binary.BigEndian.PutUint32(value[i+4:i+8], istmp.IpAddress)
		binary.BigEndian.PutUint32(value[i+8:i+12], istmp.SubnetMask)
		i += 12
	}
	tlv.Base.Length = uint8(length)
	tlv.Base.Value = value
	data, err := tlv.Base.Serialize()
	if err != nil {
		return data, err
	}
	return data, nil
}

/*
	Inter-Domain Routing Protocol Information
	Code - 131
	Length - Total length of the value filed.
	Value -
	+------------------------+
	| Inter-Domain Info Type | 1
	+------------------------+
	| External Information   | Variable
	+------------------------+
*/

type interDomainRoutingProtoInfoTlv struct {
	Base                tlvBase
	InterDomainInfoType InterDomainInfoType
	ExternalInfo        []byte
}

func NewinterDomainRoutingProtoInfoTlv() (*interDomainRoutingProtoInfoTlv, error) {
	tlv := interDomainRoutingProtoInfoTlv{
		Base: tlvBase{
			Code: TLV_CODE_INTER_DOMAIN_ROUTING_PROTO_INFO,
		},
	}
	tlv.Base.Init()
	tlv.ExternalInfo = make([]byte, 0)
	return &tlv, nil
}

func (tlv *interDomainRoutingProtoInfoTlv) SetExternalInfo(externalInfo []byte) error {
	eitmp := make([]byte, len(externalInfo))
	copy(eitmp, externalInfo)
	tlv.ExternalInfo = eitmp
	tlv.Base.Length = uint8(1 + len(tlv.ExternalInfo))
	return nil
}

func (tlv *interDomainRoutingProtoInfoTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.Base.String())
	fmt.Fprintf(&b, "    InterDomainInfoType %s\n", tlv.InterDomainInfoType)
	fmt.Fprintf(&b, "    ExternalInfo        ")
	for _, btmp := range tlv.ExternalInfo {
		fmt.Fprintf(&b, "%02x", btmp)
	}
	fmt.Fprintf(&b, "\n")
	return b.String()
}

func (tlv *interDomainRoutingProtoInfoTlv) DecodeFromBytes(data []byte) error {
	err := tlv.Base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	if len(tlv.Base.Value) < 1 {
		return errors.New("interDomainRoutingProtoInfoTlv.DecodeFromBytes: too short")
	}
	tlv.InterDomainInfoType = InterDomainInfoType(tlv.Base.Value[0])
	externalInfo := make([]byte, len(tlv.Base.Value)-1)
	copy(externalInfo, tlv.Base.Value[1:])
	tlv.ExternalInfo = externalInfo
	return nil
}

func (tlv *interDomainRoutingProtoInfoTlv) Serialize() ([]byte, error) {
	value := make([]byte, 1+len(tlv.ExternalInfo))
	value[0] = uint8(tlv.InterDomainInfoType)
	copy(value[1:], tlv.ExternalInfo)
	tlv.Base.Length = uint8(len(value))
	tlv.Base.Value = value
	data, err := tlv.Base.Serialize()
	if err != nil {
		return data, err
	}
	return data, nil
}

/*
	IP Interface Address
	Code - 132
	Length - Total length of the value field.
	Value -
	+------------------------+
	| IP Address             | 4
	+------------------------+
	:                        :
	:                        :
	+------------------------+
	| IP Address             | 4
	+------------------------+
*/

type ipInterfaceAddressTlv struct {
	Base        tlvBase
	IpAddresses []uint32
}

func NewipInterfaceAddressTlv() (*ipInterfaceAddressTlv, error) {
	tlv := ipInterfaceAddressTlv{
		Base: tlvBase{
			Code: TLV_CODE_IP_INTERFACE_ADDRESS,
		},
	}
	tlv.Base.Init()
	tlv.IpAddresses = make([]uint32, 0)
	return &tlv, nil
}

func (tlv *ipInterfaceAddressTlv) AddIpAddress(ipAddress uint32) error {
	for _, iatmp := range tlv.IpAddresses {
		if ipAddress == iatmp {
			return nil
		}
	}
	length := len(tlv.IpAddresses)
	if length+4 > 255 {
		return errors.New("ipInterfaceAddressTlv.AddIpAddress: size over")
	}
	tlv.IpAddresses = append(tlv.IpAddresses, ipAddress)
	tlv.Base.Length = uint8(length + 4)
	return nil
}

func (tlv *ipInterfaceAddressTlv) RemoveIpAddress(ipAddress uint32) error {
	ipAddresses := make([]uint32, 0)
	for _, iatmp := range tlv.IpAddresses {
		if ipAddress != iatmp {
			ipAddresses = append(ipAddresses, iatmp)
		}
	}
	tlv.IpAddresses = ipAddresses
	tlv.Base.Length = uint8(len(tlv.IpAddresses) * 4)
	return nil
}

func (tlv *ipInterfaceAddressTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.Base.String())
	for _, iatmp := range tlv.IpAddresses {
		fmt.Fprintf(&b, "    IPAddress           %08x\n", iatmp)
	}
	return b.String()
}

func (tlv *ipInterfaceAddressTlv) DecodeFromBytes(data []byte) error {
	err := tlv.Base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	ipAddresses := make([]uint32, 0)
	consumed := 0
	for i := 0; i < len(tlv.Base.Value); i += 4 {
		if i+4 > len(tlv.Base.Value) {
			return errors.New("ipInterfaceAddressTlv.DecodeFromBytes: value length overflow")
		}
		ipAddresses = append(ipAddresses, binary.BigEndian.Uint32(tlv.Base.Value[i:i+4]))
		consumed += 4
	}
	if consumed != len(tlv.Base.Value) {
		return errors.New("ipInterfaceAddressTlv.DecodeFromBytes: value length mismatch")
	}
	tlv.IpAddresses = ipAddresses
	return nil
}

func (tlv *ipInterfaceAddressTlv) Serialize() ([]byte, error) {
	length := len(tlv.IpAddresses) * 4
	value := make([]byte, length)
	i := 0
	for _, iatmp := range tlv.IpAddresses {
		binary.BigEndian.PutUint32(value[i:i+4], iatmp)
		i += 4
	}
	tlv.Base.Length = uint8(length)
	tlv.Base.Value = value
	data, err := tlv.Base.Serialize()
	if err != nil {
		return data, err
	}
	return data, nil
}

/*
	Authentication Information
	Code - 133
	Length - Total length of the value field.
	Value - TBD.
*/
