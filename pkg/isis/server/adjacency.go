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

package server

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/m-asama/golsr/pkg/isis/packet"
)

type AdjUsage uint8

const (
	_ AdjUsage = iota
	ADJ_USAGE_NONE
	ADJ_USAGE_LEVEL1
	ADJ_USAGE_LEVEL2
	ADJ_USAGE_LEVEL1AND2
)

func (adjUsage AdjUsage) String() string {
	switch adjUsage {
	case ADJ_USAGE_NONE:
		return "ADJ_USAGE_NONE"
	case ADJ_USAGE_LEVEL1:
		return "ADJ_USAGE_LEVEL1"
	case ADJ_USAGE_LEVEL2:
		return "ADJ_USAGE_LEVEL2"
	case ADJ_USAGE_LEVEL1AND2:
		return "ADJ_USAGE_LEVEL1AND2"
	}
	log.Infof("")
	panic("")
	return fmt.Sprintf("AdjUsage(%d)", adjUsage)
}

type AdjType uint8

const (
	_ AdjType = iota
	ADJ_TYPE_LEVEL1_LAN
	ADJ_TYPE_LEVEL2_LAN
	ADJ_TYPE_P2P
)

func (adjType AdjType) String() string {
	switch adjType {
	case ADJ_TYPE_LEVEL1_LAN:
		return "ADJ_TYPE_LEVEL1_LAN"
	case ADJ_TYPE_LEVEL2_LAN:
		return "ADJ_TYPE_LEVEL2_LAN"
	case ADJ_TYPE_P2P:
		return "ADJ_TYPE_P2P"
	}
	log.Infof("")
	panic("")
	return fmt.Sprintf("AdjType(%d)", adjType)
}

type Adjacency struct {
	adjState          packet.Adj3wayState
	adjUsage          AdjUsage
	adjType           AdjType
	ipv4Supported     bool
	ipv6Supported     bool
	areaAddresses     [][]byte
	ipv4Addresses     []uint32
	ipv6Addresses     [][4]uint32
	lanAddress        [packet.SYSTEM_ID_LENGTH]byte
	systemId          [packet.SYSTEM_ID_LENGTH]byte
	priority          uint8                            // LAN
	lanId             [packet.NEIGHBOUR_ID_LENGTH]byte // LAN
	circuitId         uint8                            // P2P
	extendedCircuitId uint32                           // P2P
	holdingTime       uint16
	circuit           *Circuit
}

func NewAdjacency(circuit *Circuit) (*Adjacency, error) {
	log.Debugf("enter")
	defer log.Debugf("exit")
	adjacency := &Adjacency{}
	adjacency.areaAddresses = make([][]byte, 0)
	adjacency.ipv4Addresses = make([]uint32, 0)
	adjacency.ipv6Addresses = make([][4]uint32, 0)
	adjacency.circuit = circuit
	return adjacency, nil
}

func (adjacency *Adjacency) level(level IsisLevel) bool {
	switch level {
	case ISIS_LEVEL_1:
		return adjacency.level1()
	case ISIS_LEVEL_2:
		return adjacency.level2()
	}
	log.Infof("")
	panic("")
	return false
}

func (adjacency *Adjacency) level1() bool {
	return adjacency.adjUsage == ADJ_USAGE_LEVEL1 ||
		adjacency.adjUsage == ADJ_USAGE_LEVEL1AND2
}

func (adjacency *Adjacency) level2() bool {
	return adjacency.adjUsage == ADJ_USAGE_LEVEL2 ||
		adjacency.adjUsage == ADJ_USAGE_LEVEL1AND2
}

func (adjacency *Adjacency) level1Only() bool {
	return adjacency.adjUsage == ADJ_USAGE_LEVEL1
}

func (adjacency *Adjacency) level2Only() bool {
	return adjacency.adjUsage == ADJ_USAGE_LEVEL2
}
