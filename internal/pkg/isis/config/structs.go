package config

// draft-ietf-isis-yang-isis-cfg-25

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

type AutoCostConfig struct {
	ReferenceBandwidth *uint32 `mapstructure:"reference-bandwidth"`
	Enable             *bool   `mapstructure:"enable"`
}

type AutoCost struct {
	Config AutoCostConfig `mapstructure:"config" json:"config,omitempty"`
}

type GracefulRestartConfig struct {
	Enable          *bool   `mapstructure:"enable"`
	RestartInterval *uint16 `mapstructure:"restart-interval"`
	HelperEnable    *bool   `mapstructure:"helper-enable"`
}

type GracefulRestart struct {
	Config GracefulRestartConfig `mapstructure:"config" json:"config,omitempty"`
}

type NSRConfig struct {
	Enable *bool `mapstructure:"enable"`
}

type NSR struct {
	Config NSRConfig `mapstructure:"config" json:"config,omitempty"`
}

type NodeTagConfig struct {
	Tag *uint32 `mapstructure:"tag"`
}

type NodeTag struct {
	Config NodeTagConfig `mapstructure:"config" json:"config,omitempty"`
}

type AuthenticationConfig struct {
	KeyChain        *string `mapstructure:"key-chain"`
	Key             *string `mapstructure:"key"`
	CryptoAlgorithm *string `mapstructure:"crypto-algorithm"`
}

type AuthenticationLevel1 struct {
	Config AuthenticationConfig `mapstructure:"config" json:"config,omitempty"`
}

type AuthenticationLevel2 struct {
	Config AuthenticationConfig `mapstructure:"config" json:"config,omitempty"`
}

type Authentication struct {
	Config AuthenticationConfig `mapstructure:"config" json:"config,omitempty"`
	Level1 AuthenticationLevel1 `mapstructure:"level-1"`
	Level2 AuthenticationLevel2 `mapstructure:"level-2"`
}

type MetricTypeConfig struct {
	Value *string `mapstructure:"value"`
}

type MetricTypeLevel1 struct {
	Config MetricTypeConfig `mapstructure:"config" json:"config,omitempty"`
}

type MetricTypeLevel2 struct {
	Config MetricTypeConfig `mapstructure:"config" json:"config,omitempty"`
}

type MetricType struct {
	Config MetricTypeConfig `mapstructure:"config" json:"config,omitempty"`
	Level1 MetricTypeLevel1 `mapstructure:"level-1"`
	Level2 MetricTypeLevel2 `mapstructure:"level-2"`
}

type DefaultMetricConfig struct {
	Value *string `mapstructure:"value"`
}

type DefaultMetricLevel1 struct {
	Config DefaultMetricConfig `mapstructure:"config" json:"config,omitempty"`
}

type DefaultMetricLevel2 struct {
	Config DefaultMetricConfig `mapstructure:"config" json:"config,omitempty"`
}

type DefaultMetric struct {
	Config DefaultMetricConfig `mapstructure:"config" json:"config,omitempty"`
	Level1 DefaultMetricLevel1 `mapstructure:"level-1"`
	Level2 DefaultMetricLevel2 `mapstructure:"level-2"`
}

type AddressFamilyConfig struct {
	AddressFamily *string `mapstructure:"address-family"`
	Enable        *bool   `mapstructure:"enable"`
}

type AddressFamily struct {
	Config AddressFamilyConfig `mapstructure:"config" json:"config,omitempty"`
}

type PreferenceConfig struct {
	Internal *uint8 `mapstructure:"internal"`
	External *uint8 `mapstructure:"external"`
	Default  *uint8 `mapstructure:"default"`
}

type Preference struct {
	Config PreferenceConfig `mapstructure:"config" json:"config,omitempty"`
}

type OverloadConfig struct {
	Status *bool `mapstructure:"status"`
}

type Overload struct {
	Config OverloadConfig `mapstructure:"config" json:"config,omitempty"`
}

type OverloadMaxMetricConfig struct {
	Timeout *uint16 `mapstructure:"timeout"`
}

type OverloadMaxMetric struct {
	Config OverloadMaxMetricConfig `mapstructure:"config" json:"config,omitempty"`
}

type FastRerouteConfig struct {
}

type FastReroute struct {
	Config FastRerouteConfig `mapstructure:"config" json:"config,omitempty"`
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

type TopologyConfig struct {
	Enable *bool
	Name   *string
}

type Topology struct {
	Config        TopologyConfig `mapstructure:"config" json:"config,omitempty"`
	DefaultMetric DefaultMetric  `mapstructure:"default-metric"`
	NodeTags      []NodeTag      `mapstructure:"node-tags"`
}

type HelloPaddingConfig struct {
	Enable *bool
}

type HelloPadding struct {
	Config HelloPaddingConfig `mapstructure:"config" json:"config,omitempty"`
}

type HelloIntervalConfig struct {
	Value *uint16 `mapstructure:"value"`
}

type HelloIntervalLevel1 struct {
	Config HelloIntervalConfig `mapstructure:"config" json:"config,omitempty"`
}

type HelloIntervalLevel2 struct {
	Config HelloIntervalConfig `mapstructure:"config" json:"config,omitempty"`
}

type HelloInterval struct {
	Config HelloIntervalConfig `mapstructure:"config" json:"config,omitempty"`
	Level1 HelloIntervalLevel1 `mapstructure:"level-1"`
	Level2 HelloIntervalLevel2 `mapstructure:"level-2"`
}

type HelloMultiplierConfig struct {
	Value *uint16 `mapstructure:"value"`
}

type HelloMultiplierLevel1 struct {
	Config HelloMultiplierConfig `mapstructure:"config" json:"config,omitempty"`
}

type HelloMultiplierLevel2 struct {
	Config HelloMultiplierConfig `mapstructure:"config" json:"config,omitempty"`
}

type HelloMultiplier struct {
	Config HelloMultiplierConfig `mapstructure:"config" json:"config,omitempty"`
	Level1 HelloMultiplierLevel1 `mapstructure:"level-1"`
	Level2 HelloMultiplierLevel2 `mapstructure:"level-2"`
}

type PriorityConfig struct {
	Value *uint8 `mapstructure:"value"`
}

type PriorityLevel1 struct {
	Config PriorityConfig `mapstructure:"config" json:"config,omitempty"`
}

type PriorityLevel2 struct {
	Config PriorityConfig `mapstructure:"config" json:"config,omitempty"`
}

type Priority struct {
	Config PriorityConfig `mapstructure:"config" json:"config,omitempty"`
	Level1 PriorityLevel1 `mapstructure:"level-1"`
	Level2 PriorityLevel2 `mapstructure:"level-2"`
}

type MetricConfig struct {
	Value *string `mapstructure:"value"`
}

type MetricLevel1 struct {
	Config MetricConfig `mapstructure:"config" json:"config,omitempty"`
}

type MetricLevel2 struct {
	Config MetricConfig `mapstructure:"config" json:"config,omitempty"`
}

type Metric struct {
	Config MetricConfig `mapstructure:"config" json:"config,omitempty"`
	Level1 MetricLevel1 `mapstructure:"level-1"`
	Level2 MetricLevel2 `mapstructure:"level-2"`
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

type InterfaceLdpConfig struct {
	IgpSync *bool `mapstructure:"igp-sync"`
}

type InterfaceLdp struct {
	Config InterfaceLdpConfig `mapstructure:"config" json:"config,omitempty"`
}

type InterfaceMpls struct {
	InterfaceLdp InterfaceLdp `mapstructure:"ldp"`
}

type RemoteLfaConfig struct {
	Enable *bool `mapstructure:"enable"`
}

type RemoteLfa struct {
	Config RemoteLfaConfig `mapstructure:"config" json:"config,omitempty"`
}

type LfaLevel1 struct {
	Config    LfaConfig `mapstructure:"config" json:"config,omitempty"`
	RemoteLfa RemoteLfa `mapstructure:"remote-lfa"`
}

type LfaLevel2 struct {
	Config    LfaConfig `mapstructure:"config" json:"config,omitempty"`
	RemoteLfa RemoteLfa `mapstructure:"remote-lfa"`
}

type LfaConfig struct {
	CandidateDisabled *bool `mapstructure:"candidate-disabled"`
	Enable            *bool `mapstructure:"enable"`
}

type Lfa struct {
	Config    LfaConfig `mapstructure:"config" json:"config,omitempty"`
	RemoteLfa RemoteLfa `mapstructure:"remote-lfa"`
	Level1    LfaLevel1 `mapstructure:"level-1"`
	Level2    LfaLevel2 `mapstructure:"level-2"`
}

type InterfaceFastReroute struct {
	Lfa Lfa `mapstructure:"lfa"`
}

type InterfaceTopologyConfig struct {
	Name *string `mapstructure:"name"`
}

type InterfaceTopology struct {
	Config InterfaceTopologyConfig `mapstructure:"config" json:"config,omitempty"`
	Metric Metric                  `mapstructure:"metric"`
}

type InterfaceConfig struct {
	Name                  *string  `mapstructure:"name"`
	LevelType             *string  `mapstructure:"level-type"`
	LspPacingInterval     *uint32  `mapstructure:"lsp-pacing-interval"`
	LspRetransmitInterval *uint16  `mapstructure:"lsp-retransmit-interval"`
	Passive               *bool    `mapstructure:"passive"`
	CsnpInterval          *uint16  `mapstructure:"csnp-interval"`
	MeshGroupEnable       *string  `mapstructure:"mesh-group-enable"`
	MeshGroup             *uint8   `mapstructure:"mesh-group"`
	InterfaceType         *string  `mapstructure:"interface-type"`
	Enable                *bool    `mapstructure:"enable"`
	Tag                   []uint32 `mapstructure:"tag-list"`
	Tag64                 []uint64 `mapstructure:"tag64-list"`
	NodeFlag              *bool    `mapstructure:"node-flag"`
}

type Interface struct {
	Config              InterfaceConfig      `mapstructure:"config" json:"config,omitempty"`
	HelloPadding        HelloPadding         `mapstructure:"hello-padding"`
	HelloAuthentication Authentication       `mapstructure:"hello-authentication"`
	HelloInterval       HelloInterval        `mapstructure:"hello-interval"`
	HelloMultiplier     HelloMultiplier      `mapstructure:"hello-multiplier"`
	Priority            Priority             `mapstructure:"priority"`
	Metric              Metric               `mapstructure:"metric"`
	Bfd                 Bfd                  `mapstructure:"bfd"`
	AddressFamilies     []AddressFamily      `mapstructure:"address-families"`
	Mpls                InterfaceMpls        `mapstructure:"mpls"`
	FastReroute         InterfaceFastReroute `mapstructure:"fast-reroute"`
	Topologies          []InterfaceTopology  `mapstructure:"topologies"`
}

type Config struct {
	Enable               *bool    `mapstructure:"enable"`
	LevelType            *string  `mapstructure:"level-type"`
	SystemId             *string  `mapstructure:"system-id"`
	MaximumAreaAddresses *uint8   `mapstructure:"maximum-area-addresses"`
	AreaAddress          []string `mapstructure:"area-address-list"`
	LspMtu               *uint16  `mapstructure:"lsp-mtu"`
	LspLifetime          *uint16  `mapstructure:"lsp-lifetime"`
	LspRefresh           *uint16  `mapstructure:"lsp-refresh"`
	PoiTlv               *bool    `mapstructure:"poi-tlv"`
}

type IsisConfig struct {
	Config            Config            `mapstructure:"config" json:"config,omitempty"`
	GracefulRestart   GracefulRestart   `mapstructure:"graceful-restart"`
	NSR               NSR               `mapstructure:"nsr"`
	NodeTags          []NodeTag         `mapstructure:"node-tags"`
	MetricType        MetricType        `mapstructure:"metric-type"`
	DefaultMetric     DefaultMetric     `mapstructure:"default-metric"`
	AutoCost          AutoCost          `mapstructure:"auto-cost"`
	Authentication    Authentication    `mapstructure:"authentication"`
	AddressFamilies   []AddressFamily   `mapstructure:"address-families"`
	Mpls              Mpls              `mapstructure:"mpls"`
	SpfControl        SpfControl        `mapstructure:"spf-control"`
	FastReroute       FastReroute       `mapstructure:"fast-reroute"`
	Preference        Preference        `mapstructure:"preference"`
	Overload          Overload          `mapstructure:"overload"`
	OverloadMaxMetric OverloadMaxMetric `mapstructure:"overload-max-metric"`
	Topologies        []Topology        `mapstructure:"topologies"`
	Interfaces        []Interface       `mapstructure:"interfaces"`
}
