package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

/*
	IPv6 Reachability
	Code - 236
	Length -
	Value -
	+------------------------+
	| Metric                 | 4
	+---+---+---+------------+
	| U | X | S | Reserve    | 1
	+---+---+---+------------+
	| Prefix Length          | 1
	+------------------------+
	| Prefix                 | 1
	+------------------------+
	| Sub-TLV Length         | 1
	+------------------------+
	| Sub-TLV                | Sub-TLV Length
	+------------------------+
*/

type ipv6ReachabilityIpv6Prefix struct {
	Metric              uint32
	UpDownBit           bool
	ExternalOriginalBit bool
	SubTlvsPresence     bool
	prefixLength        uint8
	ipv6Prefix          [4]uint32
	unknownSubTlvs      [][]byte
	ipv6ReachabilityTlv *ipv6ReachabilityTlv
}

func NewIpv6ReachabilityIpv6Prefix(ipv6Prefix [4]uint32, prefixLength uint8) (*ipv6ReachabilityIpv6Prefix, error) {
	ipv6p := ipv6ReachabilityIpv6Prefix{}
	ip6ptmp := [4]uint32{ipv6Prefix[0], ipv6Prefix[1], ipv6Prefix[2], ipv6Prefix[3]}
	//copy(ip6ptmp, ipv6Prefix)
	ipv6p.ipv6Prefix = ip6ptmp
	ipv6p.prefixLength = prefixLength
	ipv6p.unknownSubTlvs = make([][]byte, 0)
	return &ipv6p, nil
}

type ipv6ReachabilityTlv struct {
	Base         tlvBase
	ipv6Prefixes []ipv6ReachabilityIpv6Prefix
}

func NewIpv6ReachabilityTlv() (*ipv6ReachabilityTlv, error) {
	tlv := ipv6ReachabilityTlv{
		Base: tlvBase{
			Code: TLV_CODE_IPV6_REACHABILITY,
		},
	}
	tlv.Base.Init()
	tlv.ipv6Prefixes = make([]ipv6ReachabilityIpv6Prefix, 0)
	return &tlv, nil
}

func (tlv *ipv6ReachabilityTlv) SetLength() {
	length := 0
	for _, ptmp := range tlv.ipv6Prefixes {
		pocts := (int(ptmp.prefixLength) + 7) / 8
		length += 6 + pocts
		for _, tlvtmp := range ptmp.unknownSubTlvs {
			length += len(tlvtmp)
		}
	}
	tlv.Base.Length = uint8(length)
}

func (tlv *ipv6ReachabilityTlv) AddIpv6Prefix(ipv6Prefix *ipv6ReachabilityIpv6Prefix) error {
	if ipv6Prefix.ipv6ReachabilityTlv != nil {
		return errors.New("ipv6ReachabilityTlv.AddIpv6Prefix: prefix already used")
	}
	length := 0
	ipv6Prefixes := make([]ipv6ReachabilityIpv6Prefix, 0)
	for _, ptmp := range tlv.ipv6Prefixes {
		if ipv6Prefix.ipv6Prefix[0] != ptmp.ipv6Prefix[0] ||
			ipv6Prefix.ipv6Prefix[1] != ptmp.ipv6Prefix[1] ||
			ipv6Prefix.ipv6Prefix[2] != ptmp.ipv6Prefix[2] ||
			ipv6Prefix.ipv6Prefix[3] != ptmp.ipv6Prefix[3] ||
			ipv6Prefix.prefixLength != ptmp.prefixLength {
			pocts := (int(ptmp.prefixLength) + 7) / 8
			length += 5 + pocts
			ipv6Prefixes = append(ipv6Prefixes, ptmp)
		}
	}
	pocts := (int(ipv6Prefix.prefixLength) + 7) / 8
	if length+6+pocts > 255 {
		return errors.New("ipv6ReachabilityTlv.AddIpv6Prefix: tlv size over")
	}
	ipv6Prefixes = append(ipv6Prefixes, *ipv6Prefix)
	tlv.ipv6Prefixes = ipv6Prefixes
	tlv.SetLength()
	return nil
}

func (tlv *ipv6ReachabilityTlv) RemoveIpv6Prefix(ipv6Prefix [4]uint32, prefixLength uint8) error {
	length := 0
	ipv6Prefixes := make([]ipv6ReachabilityIpv6Prefix, 0)
	for _, ptmp := range tlv.ipv6Prefixes {
		if ipv6Prefix[0] == ptmp.ipv6Prefix[0] &&
			ipv6Prefix[1] == ptmp.ipv6Prefix[1] &&
			ipv6Prefix[2] == ptmp.ipv6Prefix[2] &&
			ipv6Prefix[3] == ptmp.ipv6Prefix[3] &&
			prefixLength == ptmp.prefixLength {
			ptmp.ipv6ReachabilityTlv = nil
		} else {
			pocts := (int(ptmp.prefixLength) + 7) / 8
			length += 6 + pocts
			ipv6Prefixes = append(ipv6Prefixes, ptmp)
		}
	}
	tlv.ipv6Prefixes = ipv6Prefixes
	tlv.SetLength()
	return nil
}

func (tlv *ipv6ReachabilityTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.Base.String())
	for _, ptmp := range tlv.ipv6Prefixes {
		fmt.Fprintf(&b, "    ipv6Prefix          ")
		fmt.Fprintf(&b, "%08x", ptmp.ipv6Prefix[0])
		fmt.Fprintf(&b, "%08x", ptmp.ipv6Prefix[1])
		fmt.Fprintf(&b, "%08x", ptmp.ipv6Prefix[2])
		fmt.Fprintf(&b, "%08x", ptmp.ipv6Prefix[3])
		fmt.Fprintf(&b, "\n")
		fmt.Fprintf(&b, "    prefixLength        %d\n", ptmp.prefixLength)
		fmt.Fprintf(&b, "    Metric              %08x\n", ptmp.Metric)
		fmt.Fprintf(&b, "    UpDownBit           %t\n", ptmp.UpDownBit)
		fmt.Fprintf(&b, "    ExternalOriginalBit %t\n", ptmp.ExternalOriginalBit)
		fmt.Fprintf(&b, "    SubTlvsPresence     %t\n", ptmp.SubTlvsPresence)
		for _, tlvtmp := range ptmp.unknownSubTlvs {
			fmt.Fprintf(&b, "    unknownSubTlv       ")
			for _, btmp := range tlvtmp {
				fmt.Fprintf(&b, "%02x", btmp)
			}
			fmt.Fprintf(&b, "\n")
		}
	}
	return b.String()
}

func (tlv *ipv6ReachabilityTlv) DecodeFromBytes(data []byte) error {
	err := tlv.Base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	ipv6Prefixes := make([]ipv6ReachabilityIpv6Prefix, 0)
	i := 0
	for i < len(tlv.Base.Value) {
		if i+6 > len(tlv.Base.Value) {
			return errors.New("ipv6ReachabilityTlv.DecodeFromBytes: size invalid")
		}
		ltmp := int(tlv.Base.Value[i+5])
		pocts := (ltmp + 7) / 8
		if i+6+pocts > len(tlv.Base.Value) {
			return errors.New("ipv6ReachabilityTlv.DecodeFromBytes: size invalid")
		}
		ptmpb := make([]byte, 16)
		copy(ptmpb[0:pocts], tlv.Base.Value[i+6:i+6+pocts])
		//ptmp := make([]uint32, 4)
		var ptmp [4]uint32
		ptmp[0] = binary.BigEndian.Uint32(ptmpb[0:4])
		ptmp[1] = binary.BigEndian.Uint32(ptmpb[4:8])
		ptmp[2] = binary.BigEndian.Uint32(ptmpb[8:12])
		ptmp[3] = binary.BigEndian.Uint32(ptmpb[12:16])
		ipv6Prefix, err := NewIpv6ReachabilityIpv6Prefix(ptmp, uint8(ltmp))
		if err != nil {
			return err
		}
		ipv6Prefix.Metric = binary.BigEndian.Uint32(tlv.Base.Value[i+0 : i+4])
		ipv6Prefix.UpDownBit = ((tlv.Base.Value[i+4] & 0x80) == 0x80)
		ipv6Prefix.ExternalOriginalBit = ((tlv.Base.Value[i+4] & 0x40) == 0x40)
		ipv6Prefix.SubTlvsPresence = ((tlv.Base.Value[i+4] & 0x20) == 0x20)
		j := 0
		if ipv6Prefix.SubTlvsPresence {
			for i+6+pocts+j < len(tlv.Base.Value) {
				if i+6+pocts+j+2 > len(tlv.Base.Value) {
					return errors.New("ipv6ReachabilityTlv.DecodeFromBytes: size invalid")
				}
				stlvl := int(tlv.Base.Value[i+6+pocts+j+2])
				if i+6+pocts+j+2+stlvl > len(tlv.Base.Value) {
					return errors.New("ipv6ReachabilityTlv.DecodeFromBytes: size invalid")
				}
				stlv := make([]byte, 2+stlvl)
				copy(stlv, tlv.Base.Value[i+6+pocts+j:i+6+pocts+j+2+stlvl])
				ipv6Prefix.unknownSubTlvs = append(ipv6Prefix.unknownSubTlvs, stlv)
				j += 2 + stlvl
			}
		}
		ipv6Prefixes = append(ipv6Prefixes, *ipv6Prefix)
		i += 6 + pocts + j
	}
	if i != len(tlv.Base.Value) {
		return errors.New("ipv6ReachabilityTlv.DecodeFromBytes: decode error")
	}
	tlv.ipv6Prefixes = ipv6Prefixes
	return nil
}

func (tlv *ipv6ReachabilityTlv) Serialize() ([]byte, error) {
	length := int(tlv.Base.Length)
	value := make([]byte, length)
	i := 0
	for _, ptmp := range tlv.ipv6Prefixes {
		binary.BigEndian.PutUint32(value[i:i+4], ptmp.Metric)
		if ptmp.UpDownBit {
			value[i+4] |= 0x80
		}
		if ptmp.ExternalOriginalBit {
			value[i+4] |= 0x40
		}
		if ptmp.SubTlvsPresence {
			value[i+4] |= 0x20
		}
		value[i+5] = uint8(ptmp.prefixLength)
		ip6p := make([]byte, 16)
		binary.BigEndian.PutUint32(ip6p[0:4], ptmp.ipv6Prefix[0])
		binary.BigEndian.PutUint32(ip6p[4:8], ptmp.ipv6Prefix[1])
		binary.BigEndian.PutUint32(ip6p[8:12], ptmp.ipv6Prefix[2])
		binary.BigEndian.PutUint32(ip6p[12:16], ptmp.ipv6Prefix[3])
		pocts := (int(ptmp.prefixLength) + 7) / 8
		copy(value[i+6:i+6+pocts], ip6p[0:pocts])
		j := 0
		for _, ukstlv := range ptmp.unknownSubTlvs {
			copy(value[i+6+pocts+j:], ukstlv)
			j += len(ukstlv)
		}
		i += 6 + pocts + j
	}
	if i != length {
		return nil, errors.New("ipv6ReachabilityTlv.DecodeFromBytes: size error")
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
	IPv6 Interface Address
	Code - 232
	Length -
	Value -
	+------------------------+
	| Interface Address      | 16
	+------------------------+
	:                        :
	:                        *
	+------------------------+
	| Interface Address      | 16
	+------------------------+
*/

type ipv6InterfaceAddressTlv struct {
	Base          tlvBase
	ipv6Addresses [][4]uint32
}

func NewIpv6InterfaceAddressTlv() (*ipv6InterfaceAddressTlv, error) {
	tlv := ipv6InterfaceAddressTlv{
		Base: tlvBase{
			Code: TLV_CODE_IPV6_INTERFACE_ADDRESS,
		},
	}
	tlv.Base.Init()
	tlv.ipv6Addresses = make([][4]uint32, 0)
	return &tlv, nil
}

func (tlv *ipv6InterfaceAddressTlv) AddIpv6Address(ipv6Address [4]uint32) error {
	for _, iatmp := range tlv.ipv6Addresses {
		if ipv6Address[0] == iatmp[0] &&
			ipv6Address[1] == iatmp[1] &&
			ipv6Address[2] == iatmp[2] &&
			ipv6Address[3] == iatmp[3] {
			return nil
		}
	}
	length := len(tlv.ipv6Addresses)
	if length+16 > 255 {
		return errors.New("ipv6InterfaceAddressTlv.AddIpv6Address: size over")
	}
	tlv.ipv6Addresses = append(tlv.ipv6Addresses, ipv6Address)
	tlv.Base.Length = uint8(length + 16)
	return nil

}

func (tlv *ipv6InterfaceAddressTlv) RemoveIpv6Address(ipv6Address [4]uint32) error {
	ipv6Addresses := make([][4]uint32, 0)
	for _, iatmp := range tlv.ipv6Addresses {
		if ipv6Address[0] != iatmp[0] ||
			ipv6Address[1] != iatmp[1] ||
			ipv6Address[2] != iatmp[2] ||
			ipv6Address[3] != iatmp[3] {
			ipv6Addresses = append(ipv6Addresses, iatmp)
		}
	}
	tlv.ipv6Addresses = ipv6Addresses
	tlv.Base.Length = uint8(len(tlv.ipv6Addresses) * 4)
	return nil
}

func (tlv *ipv6InterfaceAddressTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.Base.String())
	for _, iatmp := range tlv.ipv6Addresses {
		fmt.Fprintf(&b, "    IPv6Address         ")
		fmt.Fprintf(&b, "%08x", iatmp[0])
		fmt.Fprintf(&b, "%08x", iatmp[1])
		fmt.Fprintf(&b, "%08x", iatmp[2])
		fmt.Fprintf(&b, "%08x", iatmp[3])
		fmt.Fprintf(&b, "\n")
	}
	return b.String()
}

func (tlv *ipv6InterfaceAddressTlv) DecodeFromBytes(data []byte) error {
	err := tlv.Base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	ipv6Addresses := make([][4]uint32, 0)
	consumed := 0
	for i := 0; i < len(tlv.Base.Value); i += 16 {
		if i+16 > len(tlv.Base.Value) {
			return errors.New("ipv6InterfaceAddressTlv.DecodeFromBytes: value length overflow")
		}
		//ip6atmp = make([]uint32, 4)
		var ip6atmp [4]uint32
		ip6atmp[0] = binary.BigEndian.Uint32(tlv.Base.Value[i+0 : i+4])
		ip6atmp[1] = binary.BigEndian.Uint32(tlv.Base.Value[i+4 : i+8])
		ip6atmp[2] = binary.BigEndian.Uint32(tlv.Base.Value[i+8 : i+12])
		ip6atmp[3] = binary.BigEndian.Uint32(tlv.Base.Value[i+12 : i+16])
		ipv6Addresses = append(ipv6Addresses, ip6atmp)
		consumed += 16
	}
	if consumed != len(tlv.Base.Value) {
		return errors.New("ipInterfaceAddressTlv.DecodeFromBytes: value length mismatch")
	}
	tlv.ipv6Addresses = ipv6Addresses
	return nil
}

func (tlv *ipv6InterfaceAddressTlv) Serialize() ([]byte, error) {
	length := len(tlv.ipv6Addresses) * 16
	value := make([]byte, length)
	i := 0
	for _, iatmp := range tlv.ipv6Addresses {
		binary.BigEndian.PutUint32(value[i+0:i+4], iatmp[0])
		binary.BigEndian.PutUint32(value[i+4:i+8], iatmp[1])
		binary.BigEndian.PutUint32(value[i+8:i+12], iatmp[2])
		binary.BigEndian.PutUint32(value[i+12:i+16], iatmp[3])
		i += 16
	}
	tlv.Base.Length = uint8(length)
	tlv.Base.Value = value
	data, err := tlv.Base.Serialize()
	if err != nil {
		return data, err
	}
	return data, nil
}
