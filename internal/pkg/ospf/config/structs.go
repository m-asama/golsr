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

package config

// draft-ietf-ospf-yang-21

type PreferenceConfig struct {
	All       *uint8 `mapstructure:"all"`
	IntraArea *uint8 `mapstructure:"intra-area"`
	InterArea *uint8 `mapstructure:"inter-area"`
	Internal  *uint8 `mapstructure:"internal"`
	External  *uint8 `mapstructure:"external"`
}

type Preference struct {
	Config PreferenceConfig `mapstructure:"config" json:"config,omitempty"`
}

type NsrConfig struct {
	Enable *bool `mapstructure:"enable"`
}

type Nsr struct {
	Config NsrConfig `mapstructure:"config" json:"config,omitempty"`
}

type GracefulRestartConfig struct {
	Enable                  *bool   `mapstructure:"enable"`
	HelperEnable            *bool   `mapstructure:"helper-enable"`
	RestartInterval         *uint16 `mapstructure:"restart-interval"`
	HelperStrictLsaChecking *bool   `mapstructure:"helper-strict-lsa-checking"`
}

type GracefulRestart struct {
	Config GracefulRestartConfig `mapstructure:"config" json:"config,omitempty"`
}

type AutoCostConfig struct {
	Enable             *bool   `mapstructure:"enable"`
	ReferenceBandwidth *uint32 `mapstructure:"reference-bandwidth"`
}

type AutoCost struct {
	Config AutoCostConfig `mapstructure:"config" json:"config,omitempty"`
}

type IetfSpfDelayConfig struct {
	InitialDelay *uint32 `mapstructure:"initial-delay"`
	ShortDelay   *uint32 `mapstructure:"short-delay"`
	LongDelay    *uint32 `mapstructure:"long-delay"`
	HoldDown     *uint32 `mapstructure:"hold-down"`
	TimeToLearn  *uint32 `mapstructure:"time-to-learn"`
}

type IetfSpfDelay struct {
	Config IetfSpfDelayConfig `mapstructure:"config" json:"config,omitempty"`
}

type SpfControlConfig struct {
	Paths *uint16 `mapstructure:"paths"`
}

type SpfControl struct {
	Config       SpfControlConfig `mapstructure:"config" json:"config,omitempty"`
	IetfSpfDelay IetfSpfDelay     `mapstructure:"ietf-spf-delay"`
}

type DatabaseControlConfig struct {
	MaxLsa *uint32 `mapstructure:"max-lsa"`
}

type DatabaseControl struct {
	Config DatabaseControlConfig `mapstructure:"config" json:"config,omitempty"`
}

type StubRouterConfig struct {
	Always *bool `mapstructure:"always"`
}

type StubRouter struct {
	Config StubRouterConfig `mapstructure:"config" json:"config,omitempty"`
}

type TeRidConfig struct {
	Ipv4RouterId *string `mapstructure:"ipv4-router-id"`
	Ipv6RouterId *string `mapstructure:"ipv6-router-id"`
}

type TeRid struct {
	Config TeRidConfig `mapstructure:"config" json:"config,omitempty"`
}

type LdpConfig struct {
}

type Ldp struct {
	Config LdpConfig `mapstructure:"config" json:"config,omitempty"`
}

type Mpls struct {
	TeRid TeRid `mapstructure:"te-rid"`
	Ldp   Ldp   `mapstructure:"ldp"`
}

type FastRerouteConfig struct {
}

type FastReroute struct {
	Config FastRerouteConfig `mapstructure:"config" json:"config,omitempty"`
}

type NodeTagConfig struct {
	Tag *uint32 `mapstructure:"tag"`
}

type NodeTag struct {
	Config NodeTagConfig `mapstructure:"config" json:"config,omitempty"`
}

type RangeConfig struct {
	Prefix    *string `mapstructure:"prefix"`
	Advertise *bool   `mapstructure:"advertise"`
	Cost      *uint32 `mapstructure:"cost"`
}

type Range struct {
	Config RangeConfig `mapstructure:"config" json:"config,omitempty"`
}

type TtlSecurityConfig struct {
	Enable *bool  `mapstructure:"enable"`
	Hops   *uint8 `mapstructure:"hops"`
}

type TtlSecurity struct {
	Config TtlSecurityConfig `mapstructure:"config" json:"config,omitempty"`
}

type AuthenticationConfig struct {
	Ospfv2AuthTrailerRfc  *string `mapstructure:"ospfv2-auth-trailer-rfc"`
	Ospfv2KeyChain        *string `mapstructure:"ospfv2-key-chain"`
	Ospfv2KeyId           *uint32 `mapstructure:"ospfv2-key-id"`
	Ospfv2Key             *string `mapstructure:"ospfv2-key"`
	Ospfv2CryptoAlgorithm *string `mapstructure:"ospfv2-crypto-algorithm"`
	Sa                    *string `mapstructure:"sa"`
	Ospfv3KeyChain        *string `mapstructure:"ospfv3-key-chain"`
	Ospfv3SaId            *uint16 `mapstructure:"ospfv3-sa-id"`
	Ospfv3Key             *string `mapstructure:"ospfv3-key"`
	Ospfv3CryptoAlgorithm *string `mapstructure:"ospfv3-crypto-algorithm"`
}

type Authentication struct {
	Config AuthenticationConfig `mapstructure:"config" json:"config,omitempty"`
}

type VirtualLinkConfig struct {
	RransitAreaId      *string `mapstructure:"transit-area-id"`
	RouterId           *string `mapstructure:"router-id"`
	HelloInterval      *uint16 `mapstructure:"hello-interval"`
	DeadInterval       *uint32 `mapstructure:"dead-interval"`
	RetransmitInterval *uint16 `mapstructure:"retransmit-interval"`
	TransmitDelay      *uint16 `mapstructure:"transmit-delay"`
	Lls                *bool   `mapstructure:"lls"`
	Enable             *bool   `mapstructure:"enable"`
}

type VirtualLink struct {
	Config         VirtualLinkConfig `mapstructure:"config" json:"config,omitempty"`
	TtlSecurity    TtlSecurity       `mapstructure:"ttl-security"`
	Authentication Authentication    `mapstructure:"authentication"`
}

type ShamLinkConfig struct {
	LocalId            *string `mapstructure:"local-id"`
	RemoteId           *string `mapstructure:"remote-id"`
	HelloInterval      *uint16 `mapstructure:"hello-interval"`
	DeadInterval       *uint32 `mapstructure:"dead-interval"`
	RetransmitInterval *uint16 `mapstructure:"retransmit-interval"`
	TransmitDelay      *uint16 `mapstructure:"transmit-delay"`
	Lls                *bool   `mapstructure:"lls"`
	Enable             *bool   `mapstructure:"enable"`
	Cost               *uint16 `mapstructure:"cost"`
	MtuIgnore          *bool   `mapstructure:"mtu-ignore"`
	PrefixSuppression  *bool   `mapstructure:"prefix-suppression"`
	TwoPartMetric      *bool   `mapstructure:"two-part-metric"`
}

type ShamLink struct {
	Config         ShamLinkConfig `mapstructure:"config" json:"config,omitempty"`
	TtlSecurity    TtlSecurity    `mapstructure:"ttl-security"`
	Authentication Authentication `mapstructure:"authentication"`
}

type MultiAreaConfig struct {
	MultiAreaId *string `mapstructure:"multi-area-id"`
	Cost        *uint16 `mapstructure:"cost"`
}

type MultiArea struct {
	Config MultiAreaConfig `mapstructure:"config" json:"config,omitempty"`
}

type StaticNeighborConfig struct {
	Identifier   *string `mapstructure:"identifier"`
	Cost         *uint16 `mapstructure:"cost"`
	PollInterval *uint16 `mapstructure:"poll-interval"`
	Priority     *uint8  `mapstructure:"priority"`
}

type StaticNeighbor struct {
	Config StaticNeighborConfig `mapstructure:"config" json:"config,omitempty"`
}

type BfdConfig struct {
	Enable                *bool   `mapstructure:"enable"`
	LocalMultiplier       *string `mapstructure:"local-multiplier"`
	DesiredMinTxInterval  *uint32 `mapstructure:"desired-min-tx-interval"`
	RequiredMinRxInterval *uint32 `mapstructure:"required-min-rx-interval"`
	MinInterval           *uint32 `mapstructure:"min-interval"`
}

type Bfd struct {
	Config BfdConfig `mapstructure:"config" json:"config,omitempty"`
}

type RemoteLfaConfig struct {
	Enable *bool `mapstructure:"enable"`
}

type RemoteLfa struct {
	Config RemoteLfaConfig `mapstructure:"config" json:"config,omitempty"`
}

type LfaConfig struct {
	CandidateEnable *bool `mapstructure:"candidate-enable"`
	Enable          *bool `mapstructure:"enable"`
}

type Lfa struct {
	Config    LfaConfig `mapstructure:"config" json:"config,omitempty"`
	RemoteLfa RemoteLfa `mapstructure:"remote-lfa"`
}

type InterfaceFastReroute struct {
	Lfa Lfa `mapstructure:"lfa"`
}

type InterfaceTopologyConfig struct {
	Name *string `mapstructure:"name"`
	Cost *uint32 `mapstructure:"cost"`
}

type InterfaceTopology struct {
	Config InterfaceTopologyConfig `mapstructure:"config" json:"config,omitempty"`
}

type InterfaceConfig struct {
	Name               *string `mapstructure:"name"`
	InterfaceType      *string `mapstructure:"interface-type"`
	Passive            *bool   `mapstructure:"passive"`
	DemandCircuit      *bool   `mapstructure:"demand-circuit"`
	Priority           *uint8  `mapstructure:"priority"`
	NodeFlag           *bool   `mapstructure:"node-flag"`
	HelloInterval      *uint16 `mapstructure:"hello-interval"`
	DeadInterval       *uint32 `mapstructure:"dead-interval"`
	RetransmitInterval *uint16 `mapstructure:"retransmit-interval"`
	TransmitDelay      *uint16 `mapstructure:"transmit-delay"`
	Lls                *bool   `mapstructure:"lls"`
	Enable             *bool   `mapstructure:"enable"`
	Cost               *uint16 `mapstructure:"cost"`
	MtuIgnore          *bool   `mapstructure:"mtu-ignore"`
	PrefixSuppression  *bool   `mapstructure:"prefix-suppression"`
	TwoPartMetric      *bool   `mapstructure:"two-part-metric"`
	InstanceId         *uint8  `mapstructure:"instance-id"`
}

type Interface struct {
	Config          InterfaceConfig      `mapstructure:"config" json:"config,omitempty"`
	MultiAreas      []*MultiArea         `mapstructure:"multi-areas"`
	StaticNeighbors []*StaticNeighbor    `mapstructure:"static-neighbors"`
	Bfd             Bfd                  `mapstructure:"bfd"`
	FastReroute     InterfaceFastReroute `mapstructure:"fast-reroute"`
	TtlSecurity     TtlSecurity          `mapstructure:"ttl-security"`
	Authentication  Authentication       `mapstructure:"authentication"`
	Topologies      []*InterfaceTopology `mapstructure:"topologies"`
}

type AreaConfig struct {
	AreaId      *string `mapstructure:"area-id"`
	AreaType    *string `mapstructure:"area-type"`
	Summary     *bool   `mapstructure:"summary"`
	DefaultCost *uint32 `mapstructure:"default-cost"`
}

type Area struct {
	Config       AreaConfig     `mapstructure:"config" json:"config,omitempty"`
	Ranges       []*Range       `mapstructure:"ranges"`
	VirtualLinks []*VirtualLink `mapstructure:"virtual-links"`
	ShamLinks    []*ShamLink    `mapstructure:"sham-links"`
	Interfaces   []*Interface   `mapstructure:"interfaces"`
}

type TopologyAreaConfig struct {
}

type TopologyArea struct {
	Config TopologyAreaConfig `mapstructure:"config" json:"config,omitempty"`
}

type TopologyConfig struct {
	Name *string `mapstructure:"name"`
}

type Topology struct {
	Config TopologyConfig  `mapstructure:"config" json:"config,omitempty"`
	Areas  []*TopologyArea `mapstructure:"areas"`
}

type Config struct {
	AddressFamily    *string `mapstructure:"address-family"`
	ExplicitRouterId *string `mapstructure:"explicit-router-id"`
	Enable           *bool   `mapstructure:"enable"`
}

type OspfConfig struct {
	Config          Config          `mapstructure:"config" json:"config,omitempty"`
	Preference      Preference      `mapstructure:"preference"`
	Nsr             Nsr             `mapstructure:"nsr"`
	GracefulRestart GracefulRestart `mapstructure:"graceful-restart"`
	AutoCost        AutoCost        `mapstructure:"auto-cost"`
	SpfControl      SpfControl      `mapstructure:"spf-control"`
	DatabaseControl DatabaseControl `mapstructure:"database-control"`
	StubRouter      StubRouter      `mapstructure:"stub-router"`
	Mpls            Mpls            `mapstructure:"mpls"`
	FastReroute     FastReroute     `mapstructure:"fast-reroute"`
	NodeTags        []*NodeTag      `mapstructure:"node-tags"`
	Areas           []*Area         `mapstructure:"areas"`
	Topologies      []*Topology     `mapstructure:"topologies"`
}

func NewOspfConfig() *OspfConfig {
	config := &OspfConfig{}
	config.NodeTags = make([]*NodeTag, 0)
	config.Areas = make([]*Area, 0)
	config.Topologies = make([]*Topology, 0)
	return config
}
