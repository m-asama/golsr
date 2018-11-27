package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

/*
	Extended IS Reachability
	code - 22
	Length -
	Value -
	+------------------------+
	| System ID + pseud      | 7
	+------------------------+
	| Default Metric         | 3
	+------------------------+
	| Length of Sub-TLVs     | 1
	+------------------------+
	| Sub-TLV type           | 1
	+------------------------+
	| Sub-TLV length         | 1
	+------------------------+
	| Sub-TLV value          |
	+------------------------+
	:                        :
	:                        :
	+------------------------+
	| System ID + pseud      | 7
	+------------------------+
	| Default Metric         | 3
	+------------------------+
	| Length of Sub-TLVs     | 1
	+------------------------+
	| Sub-TLV type           | 1
	+------------------------+
	| Sub-TLV length         | 1
	+------------------------+
	| Sub-TLV value          |
	+------------------------+
*/

type extendedIsReachabilityNeighbour struct {
	neighbourId                          []byte
	DefaultMetric                        uint32
	LengthOfSubtlvs                      uint8
	adminGroupSubTlv                     *uint32
	ipv4InterfaceAddressSubtlvs          []uint32
	ipv4NeighbourAddressSubtlvs          []uint32
	maximumLinkBandwidthSubTlv           *float32
	maximumReservableLinkBandwidthSubTlv *float32
	unreservedBandwidthSubTlv            *[8]float32
	trafficEngineeringDefaultMetric      *uint32
	unknownSubtlvs                       [][]byte
	extendedIsReachabilityTlv            *extendedIsReachabilityTlv
}

func NewExtendedIsReachabilityNeighbour(neighbourId []byte) (*extendedIsReachabilityNeighbour, error) {
	if len(neighbourId) != NEIGHBOUR_ID_LENGTH {
		return nil, errors.New("NewExtendedIsReachabilityNeighbour: neighbour ID length invalid")
	}
	nidtmp := make([]byte, NEIGHBOUR_ID_LENGTH)
	copy(nidtmp, neighbourId)
	neighbour := extendedIsReachabilityNeighbour{}
	neighbour.neighbourId = nidtmp
	neighbour.ipv4InterfaceAddressSubtlvs = make([]uint32, 0)
	neighbour.ipv4NeighbourAddressSubtlvs = make([]uint32, 0)
	neighbour.unknownSubtlvs = make([][]byte, 0)
	return &neighbour, nil
}

func (neighbour *extendedIsReachabilityNeighbour) SetLengthOfSubtlvs() {
	length := 0
	if neighbour.adminGroupSubTlv != nil {
		length += 2 + 4
	}
	length += 2 + 4*len(neighbour.ipv4InterfaceAddressSubtlvs)
	length += 2 + 4*len(neighbour.ipv4NeighbourAddressSubtlvs)
	if neighbour.maximumLinkBandwidthSubTlv != nil {
		length += 2 + 4
	}
	if neighbour.maximumReservableLinkBandwidthSubTlv != nil {
		length += 2 + 4
	}
	if neighbour.unreservedBandwidthSubTlv != nil {
		length += 2 + 32
	}
	if neighbour.trafficEngineeringDefaultMetric != nil {
		length += 2 + 4
	}
	for _, unknownSubTlv := range neighbour.unknownSubtlvs {
		length += len(unknownSubTlv)
	}
	neighbour.LengthOfSubtlvs = uint8(length)
}

func (neighbour *extendedIsReachabilityNeighbour) SetAdminGroupSubTlv(adminGroupSubTlv *uint32) {
	neighbour.adminGroupSubTlv = adminGroupSubTlv
	neighbour.SetLengthOfSubtlvs()
	if neighbour.extendedIsReachabilityTlv != nil {
		neighbour.extendedIsReachabilityTlv.SetLength()
	}
}

func (neighbour *extendedIsReachabilityNeighbour) AdminGroupSubTlv() *uint32 {
	return neighbour.adminGroupSubTlv
}

func (neighbour *extendedIsReachabilityNeighbour) AddIpv4InterfaceAddressSubTlv(ipv4IfAddrSubTlv uint32) {
	for _, ifatmp := range neighbour.ipv4InterfaceAddressSubtlvs {
		if ipv4IfAddrSubTlv == ifatmp {
			return
		}
	}
	neighbour.ipv4InterfaceAddressSubtlvs = append(neighbour.ipv4InterfaceAddressSubtlvs, ipv4IfAddrSubTlv)
	neighbour.SetLengthOfSubtlvs()
	if neighbour.extendedIsReachabilityTlv != nil {
		neighbour.extendedIsReachabilityTlv.SetLength()
	}
}

func (neighbour *extendedIsReachabilityNeighbour) RemoveIpv4InterfaceAddressSubTlv(ipv4IfAddrSubTlv uint32) {
	ipv4InterfaceAddressSubtlvs := make([]uint32, 0)
	for _, ifatmp := range neighbour.ipv4InterfaceAddressSubtlvs {
		if ipv4IfAddrSubTlv != ifatmp {
			ipv4InterfaceAddressSubtlvs = append(ipv4InterfaceAddressSubtlvs, ifatmp)
		}
	}
	neighbour.ipv4InterfaceAddressSubtlvs = ipv4InterfaceAddressSubtlvs
	neighbour.SetLengthOfSubtlvs()
	if neighbour.extendedIsReachabilityTlv != nil {
		neighbour.extendedIsReachabilityTlv.SetLength()
	}
}

func (neighbour *extendedIsReachabilityNeighbour) AddIpv4NeighbourAddressSubTlv(ipv4NeighAddrSubTlv uint32) {
	for _, natmp := range neighbour.ipv4NeighbourAddressSubtlvs {
		if ipv4NeighAddrSubTlv == natmp {
			return
		}
	}
	neighbour.ipv4NeighbourAddressSubtlvs = append(neighbour.ipv4NeighbourAddressSubtlvs, ipv4NeighAddrSubTlv)
	neighbour.SetLengthOfSubtlvs()
	if neighbour.extendedIsReachabilityTlv != nil {
		neighbour.extendedIsReachabilityTlv.SetLength()
	}
}

func (neighbour *extendedIsReachabilityNeighbour) RemoveIpv4NeighbourAddressSubTlv(ipv4NeighAddrSubTlv uint32) {
	ipv4NeighbourAddressSubtlvs := make([]uint32, 0)
	for _, natmp := range neighbour.ipv4NeighbourAddressSubtlvs {
		if ipv4NeighAddrSubTlv != natmp {
			ipv4NeighbourAddressSubtlvs = append(ipv4NeighbourAddressSubtlvs, natmp)
		}
	}
	neighbour.ipv4NeighbourAddressSubtlvs = ipv4NeighbourAddressSubtlvs
	neighbour.SetLengthOfSubtlvs()
	if neighbour.extendedIsReachabilityTlv != nil {
		neighbour.extendedIsReachabilityTlv.SetLength()
	}
}

func (neighbour *extendedIsReachabilityNeighbour) SetMaximumLinkBandwidthSubTlv(maxLBSubTlv *float32) {
	neighbour.maximumLinkBandwidthSubTlv = maxLBSubTlv
	neighbour.SetLengthOfSubtlvs()
	if neighbour.extendedIsReachabilityTlv != nil {
		neighbour.extendedIsReachabilityTlv.SetLength()
	}
}

func (neighbour *extendedIsReachabilityNeighbour) MaximumLinkBandwidthSubTlv() *float32 {
	return neighbour.maximumLinkBandwidthSubTlv
}

func (neighbour *extendedIsReachabilityNeighbour) SetMaximumReservableLinkBandwidthSubTlv(maxRLBSubtlv *float32) {
	neighbour.maximumReservableLinkBandwidthSubTlv = maxRLBSubtlv
	neighbour.SetLengthOfSubtlvs()
	if neighbour.extendedIsReachabilityTlv != nil {
		neighbour.extendedIsReachabilityTlv.SetLength()
	}
}

func (neighbour *extendedIsReachabilityNeighbour) MaximumReservableLinkBandwidthSubTlv() *float32 {
	return neighbour.maximumReservableLinkBandwidthSubTlv
}

func (neighbour *extendedIsReachabilityNeighbour) SetUnreservedBandwidthSubTlv(unreservedBSubTlv *[8]float32) {
	neighbour.unreservedBandwidthSubTlv = unreservedBSubTlv
	neighbour.SetLengthOfSubtlvs()
	if neighbour.extendedIsReachabilityTlv != nil {
		neighbour.extendedIsReachabilityTlv.SetLength()
	}
}

func (neighbour *extendedIsReachabilityNeighbour) UnreservedBandwidthSubTlv() *[8]float32 {
	return neighbour.unreservedBandwidthSubTlv
}

func (neighbour *extendedIsReachabilityNeighbour) SetTrafficEngineeringDefaultMetric(teDefaultMetric *uint32) {
	neighbour.trafficEngineeringDefaultMetric = teDefaultMetric
	neighbour.SetLengthOfSubtlvs()
	if neighbour.extendedIsReachabilityTlv != nil {
		neighbour.extendedIsReachabilityTlv.SetLength()
	}
}

func (neighbour *extendedIsReachabilityNeighbour) TrafficEngineeringDefaultMetric() *uint32 {
	return neighbour.trafficEngineeringDefaultMetric
}

type extendedIsReachabilityTlv struct {
	base       tlvBase
	neighbours []extendedIsReachabilityNeighbour
}

func NewExtendedIsReachabilityTlv() (*extendedIsReachabilityTlv, error) {
	tlv := extendedIsReachabilityTlv{
		base: tlvBase{
			code: TLV_CODE_EXTENDED_IS_REACHABILITY,
		},
	}
	tlv.base.init()
	tlv.neighbours = make([]extendedIsReachabilityNeighbour, 0)
	return &tlv, nil
}

func (tlv *extendedIsReachabilityTlv) SetLength() {
	length := 0
	for _, ntmp := range tlv.neighbours {
		length += 11 + int(ntmp.LengthOfSubtlvs)
	}
	tlv.base.length = uint8(length)
}

func (tlv *extendedIsReachabilityTlv) AddNeighbour(neighbour *extendedIsReachabilityNeighbour) error {
	if len(neighbour.neighbourId) != NEIGHBOUR_ID_LENGTH {
		return errors.New("ExtendedIsReachabilityTlv.AddNeighbour: neighbour ID length invalid")
	}
	if neighbour.extendedIsReachabilityTlv != nil {
		return errors.New("extendedIsReachabilityTlv.AddNeighbour: neighbour already used")
	}
	length := 0
	neighbours := make([]extendedIsReachabilityNeighbour, 0)
	for _, ntmp := range tlv.neighbours {
		if !bytes.Equal(neighbour.neighbourId, ntmp.neighbourId) {
			length += 11 + int(ntmp.LengthOfSubtlvs)
			neighbours = append(neighbours, ntmp)
		}
	}
	if length+11+int(neighbour.LengthOfSubtlvs) > 255 {
		return errors.New("extendedIsReachabilityTlv.AddNeighbour: tlv size over")
	}
	neighbours = append(neighbours, *neighbour)
	tlv.neighbours = neighbours
	tlv.SetLength()
	return nil
}

func (tlv *extendedIsReachabilityTlv) RemoveNeighbour(neighbourId []byte) error {
	length := 0
	neighbours := make([]extendedIsReachabilityNeighbour, 0)
	for _, ntmp := range tlv.neighbours {
		if bytes.Equal(neighbourId, ntmp.neighbourId) {
			ntmp.extendedIsReachabilityTlv = nil
		} else {
			length += 11 + int(ntmp.LengthOfSubtlvs)
			neighbours = append(neighbours, ntmp)
		}
	}
	tlv.neighbours = neighbours
	tlv.SetLength()
	return nil
}

func (tlv *extendedIsReachabilityTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.base.String())
	for i, ntmp := range tlv.neighbours {
		fmt.Fprintf(&b, "    Neighbour[%d]\n", i)
		fmt.Fprintf(&b, "        NeighbourId             ")
		for _, btmp := range ntmp.neighbourId {
			fmt.Fprintf(&b, "%02x", btmp)
		}
		fmt.Fprintf(&b, "\n")
		fmt.Fprintf(&b, "        DefaultMetric           %d\n", ntmp.DefaultMetric)
		fmt.Fprintf(&b, "        LengthOfSubtlvs         %d\n", ntmp.LengthOfSubtlvs)
		if ntmp.adminGroupSubTlv != nil {
			fmt.Fprintf(&b, "        AdminGroupSubTlv        %d\n", *ntmp.adminGroupSubTlv)
		}
		for _, iatmp := range ntmp.ipv4InterfaceAddressSubtlvs {
			fmt.Fprintf(&b, "        ipv4InterfaceAddressSubtlvs %d\n", iatmp)
		}
		for _, natmp := range ntmp.ipv4NeighbourAddressSubtlvs {
			fmt.Fprintf(&b, "        ipv4NeighbourAddressSubtlvs %d\n", natmp)
		}
		if ntmp.maximumLinkBandwidthSubTlv != nil {
			fmt.Fprintf(&b, "        maxLBSubTlv             %f\n", *ntmp.maximumLinkBandwidthSubTlv)
		}
		if ntmp.maximumReservableLinkBandwidthSubTlv != nil {
			fmt.Fprintf(&b, "        maxRLBSubTlv            %f\n", *ntmp.maximumReservableLinkBandwidthSubTlv)
		}
		if ntmp.unreservedBandwidthSubTlv != nil {
			for j := 0; j < 8; j++ {
				fmt.Fprintf(&b, "        unreservedBSubTlv       %f\n", ntmp.unreservedBandwidthSubTlv[j])
			}
		}
		if ntmp.trafficEngineeringDefaultMetric != nil {
			fmt.Fprintf(&b, "        TEDefaultMetric         %d\n", *ntmp.trafficEngineeringDefaultMetric)
		}
		for _, untlv := range ntmp.unknownSubtlvs {
			fmt.Fprintf(&b, "        unknownSubtlvs          ")
			for _, btmp := range untlv {
				fmt.Fprintf(&b, "%08x", btmp)
			}
			fmt.Fprintf(&b, "\n")
		}
	}
	return b.String()
}

func (tlv *extendedIsReachabilityTlv) DecodeFromBytes(data []byte) error {
	err := tlv.base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	neighbours := make([]extendedIsReachabilityNeighbour, 0)
	i := 0
	for i < len(tlv.base.value) {
		if i+11 > len(tlv.base.value) {
			return errors.New("extendedIsReachabilityTlv.DecodeFromBytes: size invalid")
		}
		neigh, err := NewExtendedIsReachabilityNeighbour(tlv.base.value[i+0 : i+7])
		if err != nil {
			return err
		}
		neigh.DefaultMetric = binary.BigEndian.Uint32(tlv.base.value[i+6:i+10]) & 0x00ffffff
		neigh.LengthOfSubtlvs = tlv.base.value[i+10]
		j := 0
		for j < int(neigh.LengthOfSubtlvs) {
			if i+11+j+2 > len(tlv.base.value) {
				return errors.New("extendedIsReachabilityTlv.DecodeFromBytes: size invalid")
			}
			subTlvType := int(tlv.base.value[i+11+j+0])
			subTlvLength := int(tlv.base.value[i+11+j+1])
			if i+11+j+2+subTlvLength > len(tlv.base.value) {
				return errors.New("extendedIsReachabilityTlv.DecodeFromBytes: size invalid")
			}
			subTlvValue := tlv.base.value[i+11+j+2 : i+11+j+2+subTlvLength]
			switch subTlvType {
			case 3: // Administrative group (color)
				if subTlvLength != 4 {
					errstr := "extendedIsReachabilityTlv.DecodeFromBytes: "
					errstr += "Administrative group size invalid"
					return errors.New(errstr)
				}
				adminGroup := binary.BigEndian.Uint32(subTlvValue[0:4])
				neigh.adminGroupSubTlv = &adminGroup
			case 6: // IPv4 interface address
				if subTlvLength != 4 {
					errstr := "extendedIsReachabilityTlv.DecodeFromBytes: "
					errstr += "IPv4 interface address size invalid"
					return errors.New(errstr)
				}
				ip4IfAddr := binary.BigEndian.Uint32(subTlvValue[0:4])
				neigh.ipv4InterfaceAddressSubtlvs = append(neigh.ipv4InterfaceAddressSubtlvs, ip4IfAddr)
			case 8: // IPv4 neighbor address
				if subTlvLength != 4 {
					errstr := "extendedIsReachabilityTlv.DecodeFromBytes: "
					errstr += "IPv4 neighbor address size invalid"
					return errors.New(errstr)
				}
				ip4NeighAddr := binary.BigEndian.Uint32(subTlvValue[0:4])
				neigh.ipv4NeighbourAddressSubtlvs = append(neigh.ipv4NeighbourAddressSubtlvs, ip4NeighAddr)
			case 9: // Maximum link bandwidth
				if subTlvLength != 4 {
					errstr := "extendedIsReachabilityTlv.DecodeFromBytes: "
					errstr += "Maximum link bandwidth size invalid"
					return errors.New(errstr)
				}
				maxLBtmp := binary.BigEndian.Uint32(subTlvValue[0:4])
				maxLB := math.Float32frombits(maxLBtmp)
				neigh.maximumLinkBandwidthSubTlv = &maxLB
			case 10: // Maximum reservable link bandwidth
				if subTlvLength != 4 {
					errstr := "extendedIsReachabilityTlv.DecodeFromBytes: "
					errstr += "Maximum reservable link bandwidth size invalid"
					return errors.New(errstr)
				}

				maxRLBtmp := binary.BigEndian.Uint32(subTlvValue[0:4])
				maxRLB := math.Float32frombits(maxRLBtmp)
				neigh.maximumReservableLinkBandwidthSubTlv = &maxRLB
			case 11: // Unreserved bandwidth
				if subTlvLength != 32 {
					errstr := "extendedIsReachabilityTlv.DecodeFromBytes: "
					errstr += "Unreserved bandwidth size invalid"
					return errors.New(errstr)
				}
				var ub [8]float32
				for k := 0; k < 8; k++ {
					ubtmp := binary.BigEndian.Uint32(subTlvValue[(k * 4) : (k*4)+4])
					ub[k] = math.Float32frombits(ubtmp)
				}
				neigh.unreservedBandwidthSubTlv = &ub
			case 18: // TE Default metric
				if subTlvLength != 4 {
					errstr := "extendedIsReachabilityTlv.DecodeFromBytes: "
					errstr += "TE Default metric size invalid"
					return errors.New(errstr)
				}
				tedm := binary.BigEndian.Uint32(subTlvValue[0:4])
				neigh.trafficEngineeringDefaultMetric = &tedm
			default:
				if subTlvLength != len(subTlvValue) {
					errstr := "extendedIsReachabilityTlv.DecodeFromBytes: "
					errstr += "unknownSubtlvs size invalid"
					return errors.New(errstr)
				}
				neigh.unknownSubtlvs = append(neigh.unknownSubtlvs, subTlvValue)
			}
			j += 2 + subTlvLength
		}
		if j != int(neigh.LengthOfSubtlvs) {
			return errors.New("extendedIsReachabilityTlv.DecodeFromBytes: size invalid")
		}
		neighbours = append(neighbours, *neigh)
		i += 11 + j
	}
	if i != len(tlv.base.value) {
		return errors.New("extendedIsReachabilityTlv.DecodeFromBytes: size invalid")
	}
	tlv.neighbours = neighbours
	return nil
}

func (tlv *extendedIsReachabilityTlv) Serialize() ([]byte, error) {
	length := int(tlv.base.length)
	value := make([]byte, length)
	i := 0
	for _, neigh := range tlv.neighbours {
		if i+11+int(neigh.LengthOfSubtlvs) > len(value) {
			return nil, errors.New("extendedIsReachabilityTlv.Serialize: size over")
		}
		copy(value[i:i+7], neigh.neighbourId)
		i += 7
		dmtmp := make([]byte, 4)
		binary.BigEndian.PutUint32(dmtmp[0:4], neigh.DefaultMetric)
		copy(value[i:i+3], dmtmp[1:4])
		i += 3
		value[i] = neigh.LengthOfSubtlvs
		i += 1
		if neigh.adminGroupSubTlv != nil {
			value[i+0] = 3
			value[i+1] = 4
			binary.BigEndian.PutUint32(value[i+2:i+6], *neigh.adminGroupSubTlv)
			i += 6
		}
		for _, ip4ifa := range neigh.ipv4InterfaceAddressSubtlvs {
			value[i+0] = 6
			value[i+1] = 4
			binary.BigEndian.PutUint32(value[i+2:i+6], ip4ifa)
			i += 6
		}
		for _, ip4neigha := range neigh.ipv4NeighbourAddressSubtlvs {
			value[i+0] = 8
			value[i+1] = 4
			binary.BigEndian.PutUint32(value[i+2:i+6], ip4neigha)
			i += 6
		}
		if neigh.maximumLinkBandwidthSubTlv != nil {
			value[i+0] = 9
			value[i+1] = 4
			maxLBtmp := math.Float32bits(*neigh.maximumLinkBandwidthSubTlv)
			binary.BigEndian.PutUint32(value[i+2:i+6], maxLBtmp)
			i += 6
		}
		if neigh.maximumReservableLinkBandwidthSubTlv != nil {
			value[i+0] = 10
			value[i+1] = 4
			maxRLBtmp := math.Float32bits(*neigh.maximumReservableLinkBandwidthSubTlv)
			binary.BigEndian.PutUint32(value[i+2:i+6], maxRLBtmp)
			i += 6
		}
		if neigh.unreservedBandwidthSubTlv != nil {
			value[i+0] = 11
			value[i+1] = 32
			for j := 0; j < 8; j++ {
				ubtmpuint32 := neigh.unreservedBandwidthSubTlv[j]
				ubtmp := math.Float32bits(ubtmpuint32)
				binary.BigEndian.PutUint32(value[i+2+j*4:i+2+j*4+4], ubtmp)
			}
			i += 34
		}
		if neigh.trafficEngineeringDefaultMetric != nil {
			value[i+0] = 18
			value[i+1] = 4
			binary.BigEndian.PutUint32(value[i+2:i+6], *neigh.trafficEngineeringDefaultMetric)
			i += 6
		}
		for _, uk := range neigh.unknownSubtlvs {
			copy(value[i:i+len(uk)], uk)
			i += len(uk)
		}
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
	Traffic Engineering Router ID
	code - 134
	Length - 4
	Value -
	+------------------------+
	| Router ID              | 4
	+------------------------+
*/

type trafficEngineeringRouterIdTlv struct {
	base     tlvBase
	RouterId uint32
}

func NewTrafficEngineeringRouterIdTlv() (*trafficEngineeringRouterIdTlv, error) {
	tlv := trafficEngineeringRouterIdTlv{
		base: tlvBase{
			code: TLV_CODE_TRAFFIC_ENGINEERING_ROUTER_ID,
		},
	}
	tlv.base.init()
	return &tlv, nil
}

func (tlv *trafficEngineeringRouterIdTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.base.String())
	fmt.Fprintf(&b, "    Router ID                   0x%08x\n", tlv.RouterId)
	return b.String()
}

func (tlv *trafficEngineeringRouterIdTlv) DecodeFromBytes(data []byte) error {
	err := tlv.base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	if len(tlv.base.value) != 4 {
		return errors.New("trafficEngineeringRouterIdTlv.DecodeFromBytes: value length mismatch")
	}
	tlv.RouterId = binary.BigEndian.Uint32(tlv.base.value[0:4])
	return nil
}

func (tlv *trafficEngineeringRouterIdTlv) Serialize() ([]byte, error) {
	value := make([]byte, 4)
	binary.BigEndian.PutUint32(value[0:4], tlv.RouterId)
	tlv.base.length = uint8(len(value))
	tlv.base.value = value
	data, err := tlv.base.Serialize()
	if err != nil {
		return data, err
	}
	return data, nil
}

/*
	Extended IP Reachability
	code - 135
	Length -
	Value -
	+------------------------+
	| Metric Information     | 4
	+---+---+----------------+
	|u/d| S | Prefix length  | 1
	+---+---+----------------+
	| IPv4 prefix            | 0 - 4
	+------------------------+
	| Sub-TLV type           | 1
	+------------------------+
	| Sub-TLV length         | 1
	+------------------------+
	| Sub-TLV value          |
	+------------------------+
*/

type extendedIpReachabilityIpv4Prefix struct {
	MetricInformation         uint32
	UpDownBit                 bool
	SubtlvsPresence           bool
	prefixLength              uint8
	ipv4Prefix                uint32
	unknownSubtlvs            [][]byte
	extendedIpReachabilityTlv *extendedIpReachabilityTlv
}

func NewExtendedIpReachabilityIpv4Prefix(ipv4Prefix uint32, prefixLength uint8) (*extendedIpReachabilityIpv4Prefix, error) {
	ip4p := extendedIpReachabilityIpv4Prefix{}
	ip4p.ipv4Prefix = ipv4Prefix
	ip4p.prefixLength = prefixLength
	ip4p.unknownSubtlvs = make([][]byte, 0)
	return &ip4p, nil
}

type extendedIpReachabilityTlv struct {
	base         tlvBase
	ipv4Prefixes []extendedIpReachabilityIpv4Prefix
}

func NewExtendedIpReachabilityTlv() (*extendedIpReachabilityTlv, error) {
	tlv := extendedIpReachabilityTlv{
		base: tlvBase{
			code: TLV_CODE_EXTENDED_IP_REACHABILITY,
		},
	}
	tlv.base.init()
	tlv.ipv4Prefixes = make([]extendedIpReachabilityIpv4Prefix, 0)
	return &tlv, nil
}

func (tlv *extendedIpReachabilityTlv) SetLength() {
	length := 0
	for _, ptmp := range tlv.ipv4Prefixes {
		pocts := (int(ptmp.prefixLength) + 7) / 8
		length += 5 + pocts
		for _, tlvtmp := range ptmp.unknownSubtlvs {
			length += len(tlvtmp)
		}
	}
	tlv.base.length = uint8(length)
}

func (tlv *extendedIpReachabilityTlv) AddIpv4Prefix(ipv4Prefix *extendedIpReachabilityIpv4Prefix) error {
	if ipv4Prefix.extendedIpReachabilityTlv != nil {
		return errors.New("extendedIpReachabilityTlv.AddIpv4Prefix: prefix already used")
	}
	length := 0
	ipv4Prefixes := make([]extendedIpReachabilityIpv4Prefix, 0)
	for _, ptmp := range tlv.ipv4Prefixes {
		if ipv4Prefix.ipv4Prefix != ptmp.ipv4Prefix || ipv4Prefix.prefixLength != ptmp.prefixLength {
			pocts := (int(ptmp.prefixLength) + 7) / 8
			length += 5 + pocts
			ipv4Prefixes = append(ipv4Prefixes, ptmp)
		}
	}
	pocts := (int(ipv4Prefix.prefixLength) + 7) / 8
	if length+5+pocts > 255 {
		return errors.New("extendedIpReachabilityTlv.AddIpv4Prefix: tlv size over")
	}
	ipv4Prefixes = append(ipv4Prefixes, *ipv4Prefix)
	tlv.ipv4Prefixes = ipv4Prefixes
	tlv.SetLength()
	return nil
}

func (tlv *extendedIpReachabilityTlv) RemoveIpv4Prefix(ipv4Prefix uint32, prefixLength uint8) error {
	length := 0
	ipv4Prefixes := make([]extendedIpReachabilityIpv4Prefix, 0)
	for _, ptmp := range tlv.ipv4Prefixes {
		if ipv4Prefix == ptmp.ipv4Prefix && prefixLength == ptmp.prefixLength {
			ptmp.extendedIpReachabilityTlv = nil
		} else {
			pocts := (int(ptmp.prefixLength) + 7) / 8
			length += 5 + pocts
			ipv4Prefixes = append(ipv4Prefixes, ptmp)
		}
	}
	tlv.ipv4Prefixes = ipv4Prefixes
	tlv.SetLength()
	return nil
}

func (tlv *extendedIpReachabilityTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.base.String())
	for i, ptmp := range tlv.ipv4Prefixes {
		fmt.Fprintf(&b, "    Ipv4Prefix[%d]\n", i)
		fmt.Fprintf(&b, "        ipv4Prefix              0x%08x\n", ptmp.ipv4Prefix)
		fmt.Fprintf(&b, "        prefixLength            %d\n", ptmp.prefixLength)
		fmt.Fprintf(&b, "        MetricInformation       0x%08x\n", ptmp.MetricInformation)
		fmt.Fprintf(&b, "        UpDownBit               %t\n", ptmp.UpDownBit)
		fmt.Fprintf(&b, "        SubtlvsPresence         %t\n", ptmp.SubtlvsPresence)
		for _, tlvtmp := range ptmp.unknownSubtlvs {
			fmt.Fprintf(&b, "        unknownSubTlv           ")
			for _, btmp := range tlvtmp {
				fmt.Fprintf(&b, "%02x", btmp)
			}
			fmt.Fprintf(&b, "\n")
		}
	}
	return b.String()
}

func (tlv *extendedIpReachabilityTlv) DecodeFromBytes(data []byte) error {
	err := tlv.base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	ipv4Prefixes := make([]extendedIpReachabilityIpv4Prefix, 0)
	i := 0
	for i < len(tlv.base.value) {
		if i+5 > len(tlv.base.value) {
			return errors.New("extendedIpReachabilityTlv.DecodeFromBytes: size invalid")
		}
		ltmp := int(tlv.base.value[i+4] & 0x3f)
		pocts := (ltmp + 7) / 8
		if i+5+pocts > len(tlv.base.value) {
			return errors.New("extendedIpReachabilityTlv.DecodeFromBytes: size invalid")
		}
		ptmpb := make([]byte, 4)
		copy(ptmpb[0:pocts], tlv.base.value[i+5:i+5+pocts])
		ptmp := binary.BigEndian.Uint32(ptmpb)
		ipv4Prefix, err := NewExtendedIpReachabilityIpv4Prefix(ptmp, uint8(ltmp))
		if err != nil {
			return err
		}
		ipv4Prefix.MetricInformation = binary.BigEndian.Uint32(tlv.base.value[i+0 : i+4])
		ipv4Prefix.UpDownBit = ((tlv.base.value[i+4] & 0x80) == 0x80)
		ipv4Prefix.SubtlvsPresence = ((tlv.base.value[i+4] & 0x40) == 0x40)
		j := 0
		if ipv4Prefix.SubtlvsPresence {
			for i+5+pocts+j < len(tlv.base.value) {
				if i+5+pocts+j+2 > len(tlv.base.value) {
					return errors.New("extendedIpReachabilityTlv.DecodeFromBytes: size invalid")
				}

				stlvl := int(tlv.base.value[i+5+pocts+j+2])
				if i+5+pocts+j+2+stlvl > len(tlv.base.value) {
					return errors.New("extendedIpReachabilityTlv.DecodeFromBytes: size invalid")
				}
				stlv := make([]byte, 2+stlvl)
				copy(stlv, tlv.base.value[i+5+pocts+j:i+5+pocts+j+2+stlvl])
				ipv4Prefix.unknownSubtlvs = append(ipv4Prefix.unknownSubtlvs, stlv)
				j += 2 + stlvl
			}
		}
		ipv4Prefixes = append(ipv4Prefixes, *ipv4Prefix)
		i += 5 + pocts + j
	}
	if i != len(tlv.base.value) {
		return errors.New("extendedIpReachabilityTlv.DecodeFromBytes: decode error")
	}
	tlv.ipv4Prefixes = ipv4Prefixes
	return nil
}

func (tlv *extendedIpReachabilityTlv) Serialize() ([]byte, error) {
	length := int(tlv.base.length)
	value := make([]byte, length)
	i := 0
	for _, ptmp := range tlv.ipv4Prefixes {
		binary.BigEndian.PutUint32(value[i:i+4], ptmp.MetricInformation)
		value[i+4] = ptmp.prefixLength
		if ptmp.UpDownBit {
			value[i+4] |= 0x80
		}
		if ptmp.SubtlvsPresence {
			value[i+4] |= 0x40
		}
		ip4p := make([]byte, 4)
		binary.BigEndian.PutUint32(ip4p, ptmp.ipv4Prefix)
		pocts := (int(ptmp.prefixLength) + 7) / 8
		copy(value[i+5:i+5+pocts], ip4p[0:pocts])
		j := 0
		for _, ukstlv := range ptmp.unknownSubtlvs {
			copy(value[i+5+pocts+j:], ukstlv)
			j += len(ukstlv)
		}
		i += 5 + pocts + j
	}
	if i != length {
		return nil, errors.New("extendedIpReachabilityTlv.Serialize: size error")
	}
	tlv.base.length = uint8(length)
	tlv.base.value = value
	data, err := tlv.base.Serialize()
	if err != nil {
		return data, err
	}
	return data, nil
}
