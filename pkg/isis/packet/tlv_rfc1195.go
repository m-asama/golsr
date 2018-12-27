package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

/*
	IP Internal Reachability Information
	code - 128
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
	base      tlvBase
	ipSubnets []ipInternalReachInfoIpSubnet
}

func NewIpInternalReachInfoTlv() (*ipInternalReachInfoTlv, error) {
	tlv := ipInternalReachInfoTlv{
		base: tlvBase{
			code: TLV_CODE_IP_INTERNAL_REACH_INFO,
		},
	}
	tlv.base.init()
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
	tlv.base.length = uint8(length + 12)
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
	tlv.base.length = uint8(length)
	return nil
}

func (tlv *ipInternalReachInfoTlv) TlvCode() TlvCode {
	return tlv.base.code
}

func (tlv *ipInternalReachInfoTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.base.String())
	for i, istmp := range tlv.ipSubnets {
		fmt.Fprintf(&b, "    IpSubnet[%d]\n", i)
		fmt.Fprintf(&b, "        DefaultMetric           %d\n", istmp.DefaultMetric)
		fmt.Fprintf(&b, "        DefaultMetricType       %s\n", istmp.DefaultMetricType)
		fmt.Fprintf(&b, "        DelayMetric             %d\n", istmp.DelayMetric)
		fmt.Fprintf(&b, "        DelayMetricSupported    %t\n", istmp.DelayMetricSupported)
		fmt.Fprintf(&b, "        ExpenseMetric           %d\n", istmp.ExpenseMetric)
		fmt.Fprintf(&b, "        ExpenseMetricSupported  %t\n", istmp.ExpenseMetricSupported)
		fmt.Fprintf(&b, "        ErrorMetric             %d\n", istmp.ErrorMetric)
		fmt.Fprintf(&b, "        ErrorMetricSupported    %t\n", istmp.ErrorMetricSupported)
		fmt.Fprintf(&b, "        IP Address              0x%08x", istmp.IpAddress)
		fmt.Fprintf(&b, "        Subnet Mask             0x%08x", istmp.SubnetMask)
	}
	return b.String()
}

func (tlv *ipInternalReachInfoTlv) DecodeFromBytes(data []byte) error {
	err := tlv.base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	ipSubnets := make([]ipInternalReachInfoIpSubnet, 0)
	consumed := 0
	for i := 0; i < len(tlv.base.value); i += 12 {
		istmp, _ := NewIpInternalReachInfoIpSubnet()
		istmp.DefaultMetric = (tlv.base.value[i+0] & 0x3f)
		istmp.DefaultMetricType = MetricType(tlv.base.value[i+0] & 0x40)
		istmp.DelayMetric = (tlv.base.value[i+1] & 0x3f)
		istmp.DelayMetricSupported = ((tlv.base.value[i+1] & 0x80) == 0x00)
		istmp.ExpenseMetric = (tlv.base.value[i+2] & 0x3f)
		istmp.ExpenseMetricSupported = ((tlv.base.value[i+2] & 0x80) == 0x00)
		istmp.ErrorMetric = (tlv.base.value[i+3] & 0x3f)
		istmp.ErrorMetricSupported = ((tlv.base.value[i+3] & 0x80) == 0x00)
		istmp.IpAddress = binary.BigEndian.Uint32(tlv.base.value[i+4 : i+8])
		istmp.SubnetMask = binary.BigEndian.Uint32(tlv.base.value[i+8 : i+12])
		ipSubnets = append(ipSubnets, *istmp)
		consumed += 12
	}
	if consumed != len(tlv.base.value) {
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
	tlv.base.length = uint8(length)
	tlv.base.value = value
	data, err := tlv.base.Serialize()
	if err != nil {
		return data, err
	}
	return data, nil
}

/*
	Protocols Supported
	code - 129
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
	base   tlvBase
	nlpIds []NlpId
}

func NewProtocolsSupportedTlv() (*protocolsSupportedTlv, error) {
	tlv := protocolsSupportedTlv{
		base: tlvBase{
			code: TLV_CODE_PROTOCOLS_SUPPORTED,
		},
	}
	tlv.base.init()
	tlv.nlpIds = make([]NlpId, 0)
	return &tlv, nil
}

func (tlv *protocolsSupportedTlv) ProtocolsSupported() []NlpId {
	nlpIds := make([]NlpId, 0)
	for _, nlpId := range tlv.nlpIds {
		nlpIds = append(nlpIds, nlpId)
	}
	return nlpIds
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
	tlv.base.length = uint8(length + 1)
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
	tlv.base.length = uint8(len(tlv.nlpIds))
	return nil
}

func (tlv *protocolsSupportedTlv) TlvCode() TlvCode {
	return tlv.base.code
}

func (tlv *protocolsSupportedTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.base.String())
	for _, nitmp := range tlv.nlpIds {
		fmt.Fprintf(&b, "    NLP ID                      %s\n", nitmp)
	}
	return b.String()
}

func (tlv *protocolsSupportedTlv) DecodeFromBytes(data []byte) error {
	err := tlv.base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	nlpIds := make([]NlpId, 0)
	consumed := 0
	for i := 0; i < len(tlv.base.value); i++ {
		if i+1 > len(tlv.base.value) {
			return errors.New("ProtocolsSupportedTlv.DecodeFromBytes: value length overflow")
		}
		nlpIds = append(nlpIds, NlpId(tlv.base.value[i]))
		consumed++
	}
	if consumed != len(tlv.base.value) {
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
	tlv.base.length = uint8(length)
	tlv.base.value = value
	data, err := tlv.base.Serialize()
	if err != nil {
		return data, err
	}
	return data, nil
}

/*
	IP External Reachability Information
	code - 130
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
	base      tlvBase
	ipSubnets []ipExternalReachInfoIpSubnet
}

func NewIpExternalReachInfoTlv() (*ipExternalReachInfoTlv, error) {
	tlv := ipExternalReachInfoTlv{
		base: tlvBase{
			code: TLV_CODE_IP_EXTERNAL_REACH_INFO,
		},
	}
	tlv.base.init()
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
	tlv.base.length = uint8(length + 12)
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
	tlv.base.length = uint8(length)
	return nil
}

func (tlv *ipExternalReachInfoTlv) TlvCode() TlvCode {
	return tlv.base.code
}

func (tlv *ipExternalReachInfoTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.base.String())
	for i, istmp := range tlv.ipSubnets {
		fmt.Fprintf(&b, "    IpSubnet[%d]\n", i)
		fmt.Fprintf(&b, "        DefaultMetric           %d\n", istmp.DefaultMetric)
		fmt.Fprintf(&b, "        DefaultMetricType       %s\n", istmp.DefaultMetricType)
		fmt.Fprintf(&b, "        DelayMetric             %d\n", istmp.DelayMetric)
		fmt.Fprintf(&b, "        DelayMetricSupported    %t\n", istmp.DelayMetricSupported)
		fmt.Fprintf(&b, "        ExpenseMetric           %d\n", istmp.ExpenseMetric)
		fmt.Fprintf(&b, "        ExpenseMetricSupported  %t\n", istmp.ExpenseMetricSupported)
		fmt.Fprintf(&b, "        ErrorMetric             %d\n", istmp.ErrorMetric)
		fmt.Fprintf(&b, "        ErrorMetricSupported    %t\n", istmp.ErrorMetricSupported)
		fmt.Fprintf(&b, "        IP Address              0x%08x", istmp.IpAddress)
		fmt.Fprintf(&b, "        Subnet Mask             0x%08x", istmp.SubnetMask)
	}
	return b.String()
}

func (tlv *ipExternalReachInfoTlv) DecodeFromBytes(data []byte) error {
	err := tlv.base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	ipSubnets := make([]ipExternalReachInfoIpSubnet, 0)
	consumed := 0
	for i := 0; i < len(tlv.base.value); i += 12 {
		istmp, _ := NewIpExternalReachInfoIpSubnet()
		istmp.DefaultMetric = (tlv.base.value[i+0] & 0x3f)
		istmp.DefaultMetricType = MetricType(tlv.base.value[i+0] & 0x40)
		istmp.DelayMetric = (tlv.base.value[i+1] & 0x3f)
		istmp.DelayMetricSupported = ((tlv.base.value[i+1] & 0x80) == 0x00)
		istmp.ExpenseMetric = (tlv.base.value[i+2] & 0x3f)
		istmp.ExpenseMetricSupported = ((tlv.base.value[i+2] & 0x80) == 0x00)
		istmp.ErrorMetric = (tlv.base.value[i+3] & 0x3f)
		istmp.ErrorMetricSupported = ((tlv.base.value[i+3] & 0x80) == 0x00)
		istmp.IpAddress = binary.BigEndian.Uint32(tlv.base.value[i+4 : i+8])
		istmp.SubnetMask = binary.BigEndian.Uint32(tlv.base.value[i+8 : i+12])
		ipSubnets = append(ipSubnets, *istmp)
		consumed += 12
	}
	if consumed != len(tlv.base.value) {
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
	tlv.base.length = uint8(length)
	tlv.base.value = value
	data, err := tlv.base.Serialize()
	if err != nil {
		return data, err
	}
	return data, nil
}

/*
	Inter-Domain Routing Protocol Information
	code - 131
	Length - Total length of the value filed.
	Value -
	+------------------------+
	| Inter-Domain Info Type | 1
	+------------------------+
	| External Information   | Variable
	+------------------------+
*/

type interDomainRoutingProtoInfoTlv struct {
	base                tlvBase
	InterDomainInfoType InterDomainInfoType
	ExternalInfo        []byte
}

func NewInterDomainRoutingProtoInfoTlv() (*interDomainRoutingProtoInfoTlv, error) {
	tlv := interDomainRoutingProtoInfoTlv{
		base: tlvBase{
			code: TLV_CODE_INTER_DOMAIN_ROUTING_PROTO_INFO,
		},
	}
	tlv.base.init()
	tlv.ExternalInfo = make([]byte, 0)
	return &tlv, nil
}

func (tlv *interDomainRoutingProtoInfoTlv) SetExternalInfo(externalInfo []byte) error {
	eitmp := make([]byte, len(externalInfo))
	copy(eitmp, externalInfo)
	tlv.ExternalInfo = eitmp
	tlv.base.length = uint8(1 + len(tlv.ExternalInfo))
	return nil
}

func (tlv *interDomainRoutingProtoInfoTlv) TlvCode() TlvCode {
	return tlv.base.code
}

func (tlv *interDomainRoutingProtoInfoTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.base.String())
	fmt.Fprintf(&b, "    InterDomainInfoType         %s\n", tlv.InterDomainInfoType)
	fmt.Fprintf(&b, "    ExternalInfo                ")
	for _, btmp := range tlv.ExternalInfo {
		fmt.Fprintf(&b, "%02x", btmp)
	}
	fmt.Fprintf(&b, "\n")
	return b.String()
}

func (tlv *interDomainRoutingProtoInfoTlv) DecodeFromBytes(data []byte) error {
	err := tlv.base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	if len(tlv.base.value) < 1 {
		return errors.New("interDomainRoutingProtoInfoTlv.DecodeFromBytes: too short")
	}
	tlv.InterDomainInfoType = InterDomainInfoType(tlv.base.value[0])
	externalInfo := make([]byte, len(tlv.base.value)-1)
	copy(externalInfo, tlv.base.value[1:])
	tlv.ExternalInfo = externalInfo
	return nil
}

func (tlv *interDomainRoutingProtoInfoTlv) Serialize() ([]byte, error) {
	value := make([]byte, 1+len(tlv.ExternalInfo))
	value[0] = uint8(tlv.InterDomainInfoType)
	copy(value[1:], tlv.ExternalInfo)
	tlv.base.length = uint8(len(value))
	tlv.base.value = value
	data, err := tlv.base.Serialize()
	if err != nil {
		return data, err
	}
	return data, nil
}

/*
	IP Interface Address
	code - 132
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
	base        tlvBase
	ipAddresses []uint32
}

func NewIpInterfaceAddressTlv() (*ipInterfaceAddressTlv, error) {
	tlv := ipInterfaceAddressTlv{
		base: tlvBase{
			code: TLV_CODE_IP_INTERFACE_ADDRESS,
		},
	}
	tlv.base.init()
	tlv.ipAddresses = make([]uint32, 0)
	return &tlv, nil
}

func (tlv *ipInterfaceAddressTlv) IpAddresses() []uint32 {
	ipAddresses := make([]uint32, 0)
	for _, iatmp := range tlv.ipAddresses {
		ipAddresses = append(ipAddresses, iatmp)
	}
	return ipAddresses
}

func (tlv *ipInterfaceAddressTlv) AddIpAddress(ipAddress uint32) error {
	for _, iatmp := range tlv.ipAddresses {
		if ipAddress == iatmp {
			return nil
		}
	}
	length := len(tlv.ipAddresses)
	if length+4 > 255 {
		return errors.New("ipInterfaceAddressTlv.AddIpAddress: size over")
	}
	tlv.ipAddresses = append(tlv.ipAddresses, ipAddress)
	tlv.base.length = uint8(length + 4)
	return nil
}

func (tlv *ipInterfaceAddressTlv) RemoveIpAddress(ipAddress uint32) error {
	ipAddresses := make([]uint32, 0)
	for _, iatmp := range tlv.ipAddresses {
		if ipAddress != iatmp {
			ipAddresses = append(ipAddresses, iatmp)
		}
	}
	tlv.ipAddresses = ipAddresses
	tlv.base.length = uint8(len(tlv.ipAddresses) * 4)
	return nil
}

func (tlv *ipInterfaceAddressTlv) TlvCode() TlvCode {
	return tlv.base.code
}

func (tlv *ipInterfaceAddressTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.base.String())
	for _, iatmp := range tlv.ipAddresses {
		fmt.Fprintf(&b, "    IPAddress                   0x%08x\n", iatmp)
	}
	return b.String()
}

func (tlv *ipInterfaceAddressTlv) DecodeFromBytes(data []byte) error {
	err := tlv.base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	ipAddresses := make([]uint32, 0)
	consumed := 0
	for i := 0; i < len(tlv.base.value); i += 4 {
		if i+4 > len(tlv.base.value) {
			return errors.New("ipInterfaceAddressTlv.DecodeFromBytes: value length overflow")
		}
		ipAddresses = append(ipAddresses, binary.BigEndian.Uint32(tlv.base.value[i:i+4]))
		consumed += 4
	}
	if consumed != len(tlv.base.value) {
		return errors.New("ipInterfaceAddressTlv.DecodeFromBytes: value length mismatch")
	}
	tlv.ipAddresses = ipAddresses
	return nil
}

func (tlv *ipInterfaceAddressTlv) Serialize() ([]byte, error) {
	length := len(tlv.ipAddresses) * 4
	value := make([]byte, length)
	i := 0
	for _, iatmp := range tlv.ipAddresses {
		binary.BigEndian.PutUint32(value[i:i+4], iatmp)
		i += 4
	}
	tlv.base.length = uint8(length)
	tlv.base.value = value
	data, err := tlv.base.Serialize()
	if err != nil {
		return data, err
	}
	return data, nil
}

/*
	Authentication Information
	code - 133
	Length - Total length of the value field.
	Value - TBD.
*/
