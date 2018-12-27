package server

import (
	"fmt"

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
	lanAddress        []byte
	systemId          []byte
	priority          uint8  // LAN
	lanId             []byte // LAN
	circuitId         uint8  // P2P
	extendedCircuitId uint32 // P2P
	holdingTime       uint16
	circuit           *Circuit
}

func NewAdjacency(circuit *Circuit) (*Adjacency, error) {
	adjacency := &Adjacency{}
	adjacency.areaAddresses = make([][]byte, 0)
	adjacency.ipv4Addresses = make([]uint32, 0)
	adjacency.ipv6Addresses = make([][4]uint32, 0)
	adjacency.lanAddress = make([]byte, 0)
	adjacency.systemId = make([]byte, 0)
	adjacency.lanId = make([]byte, 0)
	adjacency.circuit = circuit
	return adjacency, nil
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
