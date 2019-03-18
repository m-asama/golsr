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
	"fmt"
)

var (
	AllL1Iss = []byte{0x01, 0x80, 0xC2, 0x00, 0x00, 0x14}
	AllL2Iss = []byte{0x01, 0x80, 0xC2, 0x00, 0x00, 0x15}
	AllIss   = []byte{0x09, 0x00, 0x2B, 0x00, 0x00, 0x05}
	Llc      = []byte{0xfe, 0xfe, 0x03}
)

const (
	SYSTEM_ID_LENGTH    = 6
	NEIGHBOUR_ID_LENGTH = SYSTEM_ID_LENGTH + 1
	LSP_ID_LENGTH       = SYSTEM_ID_LENGTH + 2
)

type IsisPdu interface {
	PduType() PduType
	String() string
	DecodeFromBytes(data []byte) error
	Serialize() ([]byte, error)
}

type IsisTlv interface {
	TlvCode() TlvCode
	String() string
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
	PDU_TYPE_LEVEL1_PSNP             = 0x1a
	PDU_TYPE_LEVEL2_PSNP             = 0x1b
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
	case PDU_TYPE_LEVEL1_PSNP:
		return "PDU_TYPE_LEVEL1_PSNP"
	case PDU_TYPE_LEVEL2_PSNP:
		return "PDU_TYPE_LEVEL2_PSNP"
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

type MetricType uint8

const (
	_                    MetricType = iota
	METRIC_TYPE_INTERNAL            = 0x00
	METRIC_TYPE_EXTERNAL            = 0x40
)

func (metricType MetricType) String() string {
	switch metricType {
	case METRIC_TYPE_INTERNAL:
		return "METRIC_TYPE_INTERNAL"
	case METRIC_TYPE_EXTERNAL:
		return "METRIC_TYPE_EXTERNAL"
	}
	return fmt.Sprintf("MetricType(%d)", metricType)
}

type AuthType uint8

const (
	_                                AuthType = iota
	AUTH_TYPE_CLEARTEXT_PASSWORD              = 0x01
	AUTH_TYPE_ROUTING_DOMAIN_PRIVATE          = 0xff
)

func (authType AuthType) String() string {
	switch authType {
	case AUTH_TYPE_CLEARTEXT_PASSWORD:
		return "AUTH_TYPE_CLEARTEXT_PASSWORD"
	case AUTH_TYPE_ROUTING_DOMAIN_PRIVATE:
		return "AUTH_TYPE_ROUTING_DOMAIN_PRIVATE"
	}
	return fmt.Sprintf("AuthType(%d)", authType)
}

type NlpId uint8

const (
	_           NlpId = iota
	NLP_ID_IPV4       = 0xcc
	NLP_ID_IPV6       = 0x8e
)

func (nlpId NlpId) String() string {
	switch nlpId {
	case NLP_ID_IPV4:
		return "NLP_ID_IPV4"
	case NLP_ID_IPV6:
		return "NLP_ID_IPV6"
	}
	return fmt.Sprintf("NlpId(%d)", nlpId)
}

type InterDomainInfoType uint8

const (
	_                                 InterDomainInfoType = iota
	INTER_DOMAIN_INFO_TYPE_RESERVED                       = 0x00
	INTER_DOMAIN_INFO_TYPE_LOCAL                          = 0x01
	INTER_DOMAIN_INFO_TYPE_AS_NUM_TAG                     = 0x02
)

func (interDomainInfoType InterDomainInfoType) String() string {
	switch interDomainInfoType {
	case INTER_DOMAIN_INFO_TYPE_RESERVED:
		return "INTER_DOMAIN_INFO_TYPE_RESERVED"
	case INTER_DOMAIN_INFO_TYPE_LOCAL:
		return "INTER_DOMAIN_INFO_TYPE_LOCAL"
	case INTER_DOMAIN_INFO_TYPE_AS_NUM_TAG:
		return "INTER_DOMAIN_INFO_TYPE_AS_NUM_TAG"
	}
	return fmt.Sprintf("InterDomainInfoType(%d)", interDomainInfoType)
}

type Adj3wayState uint8

const (
	_                           Adj3wayState = iota
	ADJ_3WAY_STATE_UP                        = 0x00
	ADJ_3WAY_STATE_INITIALIZING              = 0x01
	ADJ_3WAY_STATE_DOWN                      = 0x02
)

func (adj3wayState Adj3wayState) String() string {
	switch adj3wayState {
	case ADJ_3WAY_STATE_UP:
		return "ADJ_3WAY_STATE_UP"
	case ADJ_3WAY_STATE_INITIALIZING:
		return "ADJ_3WAY_STATE_INITIALIZING"
	case ADJ_3WAY_STATE_DOWN:
		return "ADJ_3WAY_STATE_DOWN"
	}
	return fmt.Sprintf("Adj3wayState(%d)", adj3wayState)
}

type TlvCode uint8

const (
	_ TlvCode = iota
	// ISO10589
	TLV_CODE_AREA_ADDRESSES             = 0x01
	TLV_CODE_IS_NEIGHBOURS_LSP          = 0x02
	TLV_CODE_ES_NEIGHBOURS              = 0x03
	TLV_CODE_PARTITION_DESIGNATED_L2_IS = 0x04
	TLV_CODE_PREFIX_NEIGHBOURS          = 0x05
	TLV_CODE_IS_NEIGHBOURS_HELLO        = 0x06
	TLV_CODE_IS_NEIGHBOURS_VARIABLE     = 0x07
	TLV_CODE_PADDING                    = 0x08
	TLV_CODE_LSP_ENTRIES                = 0x09
	TLV_CODE_AUTH_INFO                  = 0x0a
	TLV_CODE_LSP_BUFF_SIZE              = 0x0e
	// RFC1195
	TLV_CODE_IP_INTERNAL_REACH_INFO          = 0x80
	TLV_CODE_PROTOCOLS_SUPPORTED             = 0x81
	TLV_CODE_IP_EXTERNAL_REACH_INFO          = 0x82
	TLV_CODE_INTER_DOMAIN_ROUTING_PROTO_INFO = 0x83
	TLV_CODE_IP_INTERFACE_ADDRESS            = 0x84
	TLV_CODE_AUTHENTICATION_INFO             = 0x85
	// RFC5301
	TLV_CODE_DYNAMIC_HOSTNAME = 0x89
	// RFC5303
	TLV_CODE_P2P_3WAY_ADJ = 0xf0
	// RFC5305
	TLV_CODE_EXTENDED_IS_REACHABILITY      = 0x16
	TLV_CODE_TRAFFIC_ENGINEERING_ROUTER_ID = 0x86
	TLV_CODE_EXTENDED_IP_REACHABILITY      = 0x87
	// RFC5308
	TLV_CODE_IPV6_REACHABILITY      = 0xec
	TLV_CODE_IPV6_INTERFACE_ADDRESS = 0xe8
)

func (tlvCode TlvCode) String() string {
	switch tlvCode {
	case TLV_CODE_AREA_ADDRESSES:
		return "TLV_CODE_AREA_ADDRESSES"
	case TLV_CODE_IS_NEIGHBOURS_LSP:
		return "TLV_CODE_IS_NEIGHBOURS_LSP"
	case TLV_CODE_ES_NEIGHBOURS:
		return "TLV_CODE_ES_NEIGHBOURS"
	case TLV_CODE_PARTITION_DESIGNATED_L2_IS:
		return "TLV_CODE_PARTITION_DESIGNATED_L2_IS"
	case TLV_CODE_PREFIX_NEIGHBOURS:
		return "TLV_CODE_PREFIX_NEIGHBOURS"
	case TLV_CODE_IS_NEIGHBOURS_HELLO:
		return "TLV_CODE_IS_NEIGHBOURS_HELLO"
	case TLV_CODE_IS_NEIGHBOURS_VARIABLE:
		return "TLV_CODE_IS_NEIGHBOURS_VARIABLE"
	case TLV_CODE_PADDING:
		return "TLV_CODE_PADDING"
	case TLV_CODE_LSP_ENTRIES:
		return "TLV_CODE_LSP_ENTRIES"
	case TLV_CODE_AUTH_INFO:
		return "TLV_CODE_AUTH_INFO"
	case TLV_CODE_LSP_BUFF_SIZE:
		return "TLV_CODE_LSP_BUFF_SIZE"
	case TLV_CODE_IP_INTERNAL_REACH_INFO:
		return "TLV_CODE_IP_INTERNAL_REACH_INFO"
	case TLV_CODE_PROTOCOLS_SUPPORTED:
		return "TLV_CODE_PROTOCOLS_SUPPORTED"
	case TLV_CODE_IP_EXTERNAL_REACH_INFO:
		return "TLV_CODE_IP_EXTERNAL_REACH_INFO"
	case TLV_CODE_INTER_DOMAIN_ROUTING_PROTO_INFO:
		return "TLV_CODE_INTER_DOMAIN_ROUTING_PROTO_INFO"
	case TLV_CODE_IP_INTERFACE_ADDRESS:
		return "TLV_CODE_IP_INTERFACE_ADDRESS"
	case TLV_CODE_AUTHENTICATION_INFO:
		return "TLV_CODE_AUTHENTICATION_INFO"
	case TLV_CODE_DYNAMIC_HOSTNAME:
		return "TLV_CODE_DYNAMIC_HOSTNAME"
	case TLV_CODE_P2P_3WAY_ADJ:
		return "TLV_CODE_P2P_3WAY_ADJ"
	case TLV_CODE_EXTENDED_IS_REACHABILITY:
		return "TLV_CODE_EXTENDED_IS_REACHABILITY"
	case TLV_CODE_TRAFFIC_ENGINEERING_ROUTER_ID:
		return "TLV_CODE_TRAFFIC_ENGINEERING_ROUTER_ID"
	case TLV_CODE_EXTENDED_IP_REACHABILITY:
		return "TLV_CODE_EXTENDED_IP_REACHABILITY"
	case TLV_CODE_IPV6_REACHABILITY:
		return "TLV_CODE_IPV6_REACHABILITY"
	case TLV_CODE_IPV6_INTERFACE_ADDRESS:
		return "TLV_CODE_IPV6_INTERFACE_ADDRESS"
	}
	return fmt.Sprintf("TlvCode(%d)", tlvCode)
}

func NewTlv(tlvCode TlvCode) (IsisTlv, error) {
	var tlv IsisTlv
	var err error
	switch tlvCode {
	case TLV_CODE_AREA_ADDRESSES:
		tlv, err = NewAreaAddressesTlv()
	case TLV_CODE_IS_NEIGHBOURS_LSP:
		tlv, err = NewIsNeighboursLspTlv()
	/*
	   case TLV_CODE_ES_NEIGHBOURS:
	           tlv, err = NewEsNeighboursTlv()
	*/
	case TLV_CODE_PARTITION_DESIGNATED_L2_IS:
		tlv, err = NewPartitionDesignatedL2IsTlv()
	/*
	   case TLV_CODE_PREFIX_NEIGHBOURS:
	           tlv, err = NewPrefixNeighboursTlv()
	*/
	case TLV_CODE_IS_NEIGHBOURS_HELLO:
		tlv, err = NewIsNeighboursHelloTlv()
	/*
	   case TLV_CODE_IS_NEIGHBOURS_VARIABLE:
	           tlv, err = NewIsNeighboursVariableTlv()
	*/
	case TLV_CODE_PADDING:
		tlv, err = NewPaddingTlv()
	case TLV_CODE_LSP_ENTRIES:
		tlv, err = NewLspEntriesTlv()
	case TLV_CODE_AUTH_INFO:
		tlv, err = NewAuthInfoTlv()
	case TLV_CODE_LSP_BUFF_SIZE:
		tlv, err = NewLspBuffSizeTlv()
	case TLV_CODE_IP_INTERNAL_REACH_INFO:
		tlv, err = NewIpInternalReachInfoTlv()
	case TLV_CODE_PROTOCOLS_SUPPORTED:
		tlv, err = NewProtocolsSupportedTlv()
	case TLV_CODE_IP_EXTERNAL_REACH_INFO:
		tlv, err = NewIpExternalReachInfoTlv()
	case TLV_CODE_INTER_DOMAIN_ROUTING_PROTO_INFO:
		tlv, err = NewInterDomainRoutingProtoInfoTlv()
	case TLV_CODE_IP_INTERFACE_ADDRESS:
		tlv, err = NewIpInterfaceAddressTlv()
	/*
	   case TLV_CODE_AUTHENTICATION_INFO:
	           tlv, err = NewAuthenticationInfoTlv()
	*/
	case TLV_CODE_DYNAMIC_HOSTNAME:
		tlv, err = NewDynamicHostnameTlv()
	case TLV_CODE_P2P_3WAY_ADJ:
		tlv, err = NewP2p3wayAdjacencyTlv()
	case TLV_CODE_EXTENDED_IS_REACHABILITY:
		tlv, err = NewExtendedIsReachabilityTlv()
	case TLV_CODE_TRAFFIC_ENGINEERING_ROUTER_ID:
		tlv, err = NewTrafficEngineeringRouterIdTlv()
	case TLV_CODE_EXTENDED_IP_REACHABILITY:
		tlv, err = NewExtendedIpReachabilityTlv()
	case TLV_CODE_IPV6_REACHABILITY:
		tlv, err = NewIpv6ReachabilityTlv()
	case TLV_CODE_IPV6_INTERFACE_ADDRESS:
		tlv, err = NewIpv6InterfaceAddressTlv()
	default:
		tlv, err = NewUnknownTlv(tlvCode)
	}
	return tlv, err
}
