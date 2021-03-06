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

import (
	"github.com/m-asama/golsr/internal/pkg/kernel"
)

func (config *Interface) InterfaceAddressFamiliesDefaults(isisConfig *IsisConfig) {
}

func (config *IsisConfig) AddressFamiliesDefaults() {
	var ipv4 *bool
	var ipv6 *bool
	for _, af := range config.AddressFamilies {
		if *af.Config.AddressFamily == "ipv4" {
			if af.Config.Enable == nil {
				enable := true
				af.Config.Enable = &enable
			}
			ipv4 = af.Config.Enable
		}
		if *af.Config.AddressFamily == "ipv6" {
			if af.Config.Enable == nil {
				enable := true
				af.Config.Enable = &enable
			}
			ipv6 = af.Config.Enable
		}
	}
	if ipv4 == nil {
		afstr := "ipv4"
		enable := true
		af := &AddressFamily{
			Config: AddressFamilyConfig{
				AddressFamily: &afstr,
				Enable:        &enable,
			},
		}
		config.AddressFamilies = append(config.AddressFamilies, af)
	}
	if ipv6 == nil {
		afstr := "ipv6"
		enable := true
		af := &AddressFamily{
			Config: AddressFamilyConfig{
				AddressFamily: &afstr,
				Enable:        &enable,
			},
		}
		config.AddressFamilies = append(config.AddressFamilies, af)
	}
}

func (config *NodeTag) fillDefaults() {
}

func (config *AddressFamily) fillDefaults() {
}

func (config *Topology) fillDefaults() {
	for _, nodeTag := range config.NodeTags {
		nodeTag.fillDefaults()
	}
}

func (config *InterfaceAddressFamily) fillDefaults() {
}

func (config *InterfaceTopology) fillDefaults() {
}

func (config *Interface) fillDefaults(isisConfig *IsisConfig) {
	ifaceType := kernel.IfType(0)
	if config.Config.Name != nil {
		ifaceType = kernel.IfaceType(*config.Config.Name)
	}
	// name
	// level-type
	if config.Config.LevelType == nil {
		levelType := "level-all"
		config.Config.LevelType = &levelType
	}
	// lsp-pacing-interval
	if config.Config.LspPacingInterval == nil {
		lspPacingInterval := uint32(33)
		config.Config.LspPacingInterval = &lspPacingInterval
	}
	// lsp-retransmit-interval
	if config.Config.LspRetransmitInterval == nil {
		lspRetransmitInterval := uint16(5)
		config.Config.LspRetransmitInterval = &lspRetransmitInterval
	}
	// passive
	if config.Config.Passive == nil {
		passive := false
		if ifaceType == kernel.IF_TYPE_LOOPBACK {
			passive = true
		}
		config.Config.Passive = &passive
	}
	// csnp-interval
	if config.Config.CsnpInterval == nil {
		csnpInterval := uint16(10)
		config.Config.CsnpInterval = &csnpInterval
	}
	// hello-padding
	if config.HelloPadding.Config.Enable == nil {
		enable := true
		config.HelloPadding.Config.Enable = &enable
	}
	// mesh-group-enable
	// mesh-group
	// interface-type
	if config.Config.InterfaceType == nil {
		interfaceType := "point-to-point"
		if ifaceType == kernel.IF_TYPE_BROADCAST {
			interfaceType = "broadcast"
		}
		config.Config.InterfaceType = &interfaceType
	}
	// enable
	if config.Config.Enable == nil {
		enable := true
		config.Config.Enable = &enable
	}
	// tag
	// tag64
	// node-flag
	if config.Config.NodeFlag == nil {
		nodeFlag := false
		config.Config.NodeFlag = &nodeFlag
	}
	// hello-authentication
	// hello-interval
	if config.HelloInterval.Config.Value == nil {
		value := uint16(10)
		config.HelloInterval.Config.Value = &value
	}
	if config.HelloInterval.Level1.Config.Value == nil {
		value := *config.HelloInterval.Config.Value
		config.HelloInterval.Level1.Config.Value = &value
	}
	if config.HelloInterval.Level2.Config.Value == nil {
		value := *config.HelloInterval.Config.Value
		config.HelloInterval.Level2.Config.Value = &value
	}
	// hello-multiplier
	if config.HelloMultiplier.Config.Value == nil {
		value := uint16(3)
		config.HelloMultiplier.Config.Value = &value
	}
	if config.HelloMultiplier.Level1.Config.Value == nil {
		value := *config.HelloMultiplier.Config.Value
		config.HelloMultiplier.Level1.Config.Value = &value
	}
	if config.HelloMultiplier.Level2.Config.Value == nil {
		value := *config.HelloMultiplier.Config.Value
		config.HelloMultiplier.Level2.Config.Value = &value
	}
	// priority
	if config.Priority.Config.Value == nil {
		value := uint8(64)
		config.Priority.Config.Value = &value
	}
	if config.Priority.Level1.Config.Value == nil {
		value := *config.Priority.Config.Value
		config.Priority.Level1.Config.Value = &value
	}
	if config.Priority.Level2.Config.Value == nil {
		value := *config.Priority.Config.Value
		config.Priority.Level2.Config.Value = &value
	}
	// metric
	if config.Metric.Config.Value == nil {
		value := *isisConfig.DefaultMetric.Config.Value
		config.Metric.Config.Value = &value
	}
	if config.Metric.Level1.Config.Value == nil {
		value := *config.Metric.Config.Value
		config.Metric.Level1.Config.Value = &value
	}
	if config.Metric.Level2.Config.Value == nil {
		value := *config.Metric.Config.Value
		config.Metric.Level2.Config.Value = &value
	}
	// bfd
	// address-families
	config.InterfaceAddressFamiliesDefaults(isisConfig)
	for _, af := range config.AddressFamilies {
		af.fillDefaults()
	}
	// mpls
	// fast-reroute
	// topologies
	for _, topo := range config.Topologies {
		topo.fillDefaults()
	}
}

func (config *IsisConfig) fillDefaults() {
	// enable
	if config.Config.Enable == nil {
		enable := true
		config.Config.Enable = &enable
	}
	// level-type
	if config.Config.LevelType == nil {
		levelType := "level-all"
		config.Config.LevelType = &levelType
	}
	// system-id
	// maximum-area-addresses
	if config.Config.MaximumAreaAddresses == nil {
		maximumAreaAddresses := uint8(3)
		config.Config.MaximumAreaAddresses = &maximumAreaAddresses
	}
	// area-address
	// lsp-mtu
	if config.Config.LspMtu == nil {
		lspMtu := uint16(1492)
		config.Config.LspMtu = &lspMtu
	}
	// lsp-lifetime
	if config.Config.LspLifetime == nil {
		lspLifetime := uint16(1200)
		config.Config.LspLifetime = &lspLifetime
	}
	// lsp-refresh
	if config.Config.LspRefresh == nil {
		lspRefresh := uint16(900)
		config.Config.LspRefresh = &lspRefresh
	}
	// poi-tlv
	if config.Config.PoiTlv == nil {
		poiTlv := false
		config.Config.PoiTlv = &poiTlv
	}
	// graceful-restart
	if config.GracefulRestart.Config.Enable == nil {
		enable := false
		config.GracefulRestart.Config.Enable = &enable
	}
	if config.GracefulRestart.Config.HelperEnable == nil {
		helperEnable := true
		config.GracefulRestart.Config.HelperEnable = &helperEnable
	}
	// nsr
	if config.Nsr.Config.Enable == nil {
		enable := false
		config.Nsr.Config.Enable = &enable
	}
	// node-tags
	for _, nodeTag := range config.NodeTags {
		nodeTag.fillDefaults()
	}
	// metric-type
	if config.MetricType.Config.Value == nil {
		value := "wide-only"
		config.MetricType.Config.Value = &value
	}
	if config.MetricType.Level1.Config.Value == nil {
		value := *config.MetricType.Config.Value
		config.MetricType.Level1.Config.Value = &value
	}
	if config.MetricType.Level2.Config.Value == nil {
		value := *config.MetricType.Config.Value
		config.MetricType.Level2.Config.Value = &value
	}
	// default-metric
	if config.DefaultMetric.Config.Value == nil {
		value := uint32(10)
		config.DefaultMetric.Config.Value = &value
	}
	// auto-cost
	// authentication
	// address-families
	config.AddressFamiliesDefaults()
	for _, af := range config.AddressFamilies {
		af.fillDefaults()
	}
	// mpls
	// spf-control
	// fast-reroute
	// preference
	// overload
	// overload-max-metric
	// topologies
	for _, topo := range config.Topologies {
		topo.fillDefaults()
	}
	// interfaces
	for _, iface := range config.Interfaces {
		iface.fillDefaults(config)
	}
}
