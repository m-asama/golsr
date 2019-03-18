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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

/*
	Area Addresses:
	code - 1
	Length - total length of the value field.
	Value -
	+------------------------+
	| Address Length         | 1
	+------------------------+
	| Area Address           | Address Length
	+------------------------+
	:                        :
	:                        :
	+------------------------+
	| Address Length         | 1
	+------------------------+
	| Area Address           | Address Length
	+------------------------+
*/

type areaAddressesTlv struct {
	base          tlvBase
	areaAddresses [][]byte
}

func NewAreaAddressesTlv() (*areaAddressesTlv, error) {
	tlv := areaAddressesTlv{
		base: tlvBase{
			code: TLV_CODE_AREA_ADDRESSES,
		},
	}
	tlv.base.init()
	tlv.areaAddresses = make([][]byte, 0)
	return &tlv, nil
}

func (tlv *areaAddressesTlv) AreaAddresses() [][]byte {
	areaAddresses := make([][]byte, 0)
	for _, tmp := range tlv.areaAddresses {
		areaAddress := make([]byte, len(tmp))
		copy(areaAddress, tmp)
		areaAddresses = append(areaAddresses, tmp)
	}
	return areaAddresses
}

func (tlv *areaAddressesTlv) AddAreaAddress(areaAddress []byte) error {
	length := 0
	areaAddresses := make([][]byte, 0)
	for _, eatmp := range tlv.areaAddresses {
		if bytes.Equal(areaAddress, eatmp) {
			return nil
		}
		areaAddresses = append(areaAddresses, eatmp)
		length += 1 + len(eatmp)
	}
	if length+1+len(areaAddress) > 255 {
		return errors.New("areaAddressesTlv.AddAreaAddress: size over")
	}
	areaAddresses = append(areaAddresses, areaAddress)
	tlv.areaAddresses = areaAddresses
	tlv.base.length = uint8(length + 1 + len(areaAddress))
	return nil
}

func (tlv *areaAddressesTlv) RemoveAreaAddress(areaAddress []byte) error {
	length := 0
	areaAddresses := make([][]byte, 0)
	for _, eatmp := range tlv.areaAddresses {
		if !bytes.Equal(areaAddress, eatmp) {
			areaAddresses = append(areaAddresses, eatmp)
			length += 1 + len(eatmp)
		}
	}
	tlv.areaAddresses = areaAddresses
	tlv.base.length = uint8(length)
	return nil
}

func (tlv *areaAddressesTlv) TlvCode() TlvCode {
	return tlv.base.code
}

func (tlv *areaAddressesTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.base.String())
	for _, areaAddress := range tlv.areaAddresses {
		fmt.Fprintf(&b, "    AreaAddress                 ")
		for _, btmp := range areaAddress {
			fmt.Fprintf(&b, "%02x", btmp)
		}
		fmt.Fprintf(&b, "\n")
	}
	return b.String()
}

func (tlv *areaAddressesTlv) DecodeFromBytes(data []byte) error {
	err := tlv.base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	areaAddresses := make([][]byte, 0)
	consumed := 0
	for i := 0; i < len(tlv.base.value); i += 1 + int(tlv.base.value[i]) {
		if i+1+int(tlv.base.value[i]) > len(tlv.base.value) {
			return errors.New("areaAddressesTlv.DecodeFromBytes: value length overflow")
		}
		areaAddress := make([]byte, tlv.base.value[i])
		copy(areaAddress, tlv.base.value[i+1:i+1+int(tlv.base.value[i])])
		areaAddresses = append(areaAddresses, areaAddress)
		consumed += 1 + int(tlv.base.value[i])
	}
	if consumed != len(tlv.base.value) {
		return errors.New("areaAddressesTlv.DecodeFromBytes: value length mismatch")
	}
	tlv.areaAddresses = areaAddresses
	return nil
}

func (tlv *areaAddressesTlv) Serialize() ([]byte, error) {
	length := 0
	for _, areaAddress := range tlv.areaAddresses {
		length += 1 + len(areaAddress)
	}
	value := make([]byte, length)
	i := 0
	for _, areaAddress := range tlv.areaAddresses {
		value[i] = uint8(len(areaAddress))
		copy(value[i+1:i+1+len(areaAddress)], areaAddress)
		i += 1 + len(areaAddress)
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
	Intermediate System Neighbours (LSPs)
	code - 2
	Length - 1 plus a multiple of (IDLength + 5).
	Value -
	+------------------------+
	| Virtual Flag           | 1
	+---+---+----------------+
	| 0 |I/E| Default Metric | 1
	+---+---+----------------+
	| S |I/E| Delay Metric   | 1
	+---+---+----------------+
	| S |I/E| Expense Metric | 1
	+---+---+----------------+
	| S |I/E| Error Metric   | 1
	+---+---+----------------+
	| Neighbour ID            | ID Length + 1
	+------------------------+
	:                        :
	:                        :
	+---+---+----------------+
	| 0 |I/E| Default Metric | 1
	+---+---+----------------+
	| S |I/E| Delay Metric   | 1
	+---+---+----------------+
	| S |I/E| Expense Metric | 1
	+---+---+----------------+
	| S |I/E| Error Metric   | 1
	+---+---+----------------+
	| Neighbour ID            | ID Length + 1
	+------------------------+
*/

type isNeighboursLspNeighbour struct {
	DefaultMetric          uint8
	DefaultMetricType      MetricType
	DelayMetric            uint8
	DelayMetricSupported   bool
	DelayMetricType        MetricType
	ExpenseMetric          uint8
	ExpenseMetricSupported bool
	ExpenseMetricType      MetricType
	ErrorMetric            uint8
	ErrorMetricSupported   bool
	ErrorMetricType        MetricType
	neighbourId            [NEIGHBOUR_ID_LENGTH]byte
}

func NewIsNeighboursLspNeighbour(neighbourId [NEIGHBOUR_ID_LENGTH]byte) (*isNeighboursLspNeighbour, error) {
	neighbour := isNeighboursLspNeighbour{}
	neighbour.neighbourId = neighbourId
	return &neighbour, nil
}

func (neighbour *isNeighboursLspNeighbour) NeighbourId() [NEIGHBOUR_ID_LENGTH]byte {
	return neighbour.neighbourId
}

type isNeighboursLspTlv struct {
	base        tlvBase
	VirtualFlag bool
	neighbours  []isNeighboursLspNeighbour
}

func NewIsNeighboursLspTlv() (*isNeighboursLspTlv, error) {
	tlv := isNeighboursLspTlv{
		base: tlvBase{
			code: TLV_CODE_IS_NEIGHBOURS_LSP,
		},
	}
	tlv.base.init()
	tlv.neighbours = make([]isNeighboursLspNeighbour, 0)
	return &tlv, nil
}

func (tlv *isNeighboursLspTlv) NeighbourIds() [][NEIGHBOUR_ID_LENGTH]byte {
	neighbourIds := make([][NEIGHBOUR_ID_LENGTH]byte, 0)
	for _, n := range tlv.neighbours {
		neighbourId := n.neighbourId
		neighbourIds = append(neighbourIds, neighbourId)
	}
	return neighbourIds
}

func (tlv *isNeighboursLspTlv) Neighbours() []*isNeighboursLspNeighbour {
	neighbours := make([]*isNeighboursLspNeighbour, 0)
	for _, n := range tlv.neighbours {
		neighbour := n
		neighbours = append(neighbours, &neighbour)
	}
	return neighbours
}

func (tlv *isNeighboursLspTlv) AddNeighbour(neighbour *isNeighboursLspNeighbour) error {
	length := 0
	neighbours := make([]isNeighboursLspNeighbour, 0)
	for _, ntmp := range tlv.neighbours {
		if bytes.Equal(neighbour.neighbourId[:], ntmp.neighbourId[:]) {
			return nil
		}
		neighbours = append(neighbours, ntmp)
		length += 4 + NEIGHBOUR_ID_LENGTH
	}
	if 1+length+4+NEIGHBOUR_ID_LENGTH > 255 {
		return errors.New("IsNeighboursLspTlv.AddNeighbour: size over")
	}
	neighbours = append(neighbours, *neighbour)
	tlv.neighbours = neighbours
	tlv.base.length = uint8(1 + length + 4 + NEIGHBOUR_ID_LENGTH)
	return nil
}

func (tlv *isNeighboursLspTlv) RemoveNeighbour(neighbourId [NEIGHBOUR_ID_LENGTH]byte) error {
	length := 0
	neighbours := make([]isNeighboursLspNeighbour, 0)
	for _, ntmp := range tlv.neighbours {
		if !bytes.Equal(neighbourId[:], ntmp.neighbourId[:]) {
			neighbours = append(neighbours, ntmp)
			length += 4 + NEIGHBOUR_ID_LENGTH
		}
	}
	tlv.neighbours = neighbours
	tlv.base.length = uint8(1 + length)
	return nil
}

func (tlv *isNeighboursLspTlv) TlvCode() TlvCode {
	return tlv.base.code
}

func (tlv *isNeighboursLspTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.base.String())
	fmt.Fprintf(&b, "    Virtual Flag        %t\n", tlv.VirtualFlag)
	for i, ntmp := range tlv.neighbours {
		fmt.Fprintf(&b, "    Neighbour[%d]\n", i)
		fmt.Fprintf(&b, "        DefaultMetric           %d\n", ntmp.DefaultMetric)
		fmt.Fprintf(&b, "        DefaultMetricType       %s\n", ntmp.DefaultMetricType)
		fmt.Fprintf(&b, "        DelayMetric             %d\n", ntmp.DelayMetric)
		fmt.Fprintf(&b, "        DelayMetricSupported    %t\n", ntmp.DelayMetricSupported)
		fmt.Fprintf(&b, "        DelayMetricType         %s\n", ntmp.DelayMetricType)
		fmt.Fprintf(&b, "        ExpenseMetric           %d\n", ntmp.ExpenseMetric)
		fmt.Fprintf(&b, "        ExpenseMetricSupported  %t\n", ntmp.ExpenseMetricSupported)
		fmt.Fprintf(&b, "        ExpenseMetricType       %s\n", ntmp.ExpenseMetricType)
		fmt.Fprintf(&b, "        ErrorMetric             %d\n", ntmp.ErrorMetric)
		fmt.Fprintf(&b, "        ErrorMetricSupported    %t\n", ntmp.ErrorMetricSupported)
		fmt.Fprintf(&b, "        ErrorMetricType         %s\n", ntmp.ErrorMetricType)
		fmt.Fprintf(&b, "        NeighbourId             ")
		for _, btmp := range ntmp.neighbourId {
			fmt.Fprintf(&b, "%02x", btmp)
		}
		fmt.Fprintf(&b, "\n")
	}
	return b.String()
}

func (tlv *isNeighboursLspTlv) DecodeFromBytes(data []byte) error {
	err := tlv.base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	neighbours := make([]isNeighboursLspNeighbour, 0)
	consumed := 1
	for i := 1; i < len(tlv.base.value); i += 4 + NEIGHBOUR_ID_LENGTH {
		ntmp := &isNeighboursLspNeighbour{}
		ntmp.DefaultMetric = (tlv.base.value[i+0] & 0x3f)
		ntmp.DefaultMetricType = MetricType(tlv.base.value[i+0] & 0x40)
		ntmp.DelayMetric = (tlv.base.value[i+1] & 0x3f)
		ntmp.DelayMetricSupported = ((tlv.base.value[i+1] & 0x80) == 0x00)
		ntmp.DelayMetricType = MetricType(tlv.base.value[i+1] & 0x40)
		ntmp.ExpenseMetric = (tlv.base.value[i+2] & 0x3f)
		ntmp.ExpenseMetricSupported = ((tlv.base.value[i+2] & 0x80) == 0x00)
		ntmp.ExpenseMetricType = MetricType(tlv.base.value[i+2] & 0x40)
		ntmp.ErrorMetric = (tlv.base.value[i+3] & 0x3f)
		ntmp.ErrorMetricSupported = ((tlv.base.value[i+3] & 0x80) == 0x00)
		ntmp.ErrorMetricType = MetricType(tlv.base.value[i+3] & 0x40)
		copy(ntmp.neighbourId[0:NEIGHBOUR_ID_LENGTH], tlv.base.value[i+4:i+4+NEIGHBOUR_ID_LENGTH])
		neighbours = append(neighbours, *ntmp)
		consumed += 4 + NEIGHBOUR_ID_LENGTH
	}
	if consumed != len(tlv.base.value) {
		return errors.New("IsNeighboursLspTlv.DecodeFromBytes: value length mismatch")
	}
	tlv.VirtualFlag = false
	if tlv.base.value[0] == 0x01 {
		tlv.VirtualFlag = true
	}
	tlv.neighbours = neighbours
	return nil
}

func (tlv *isNeighboursLspTlv) Serialize() ([]byte, error) {
	length := 1 + (4+NEIGHBOUR_ID_LENGTH)*len(tlv.neighbours)
	value := make([]byte, length)
	if tlv.VirtualFlag {
		value[0] = 0x01
	}
	i := 1
	for _, ntmp := range tlv.neighbours {
		value[i+0] = (ntmp.DefaultMetric & 0x3f)
		if ntmp.DefaultMetricType == METRIC_TYPE_EXTERNAL {
			value[i+0] |= 0x40
		}
		value[i+1] = (ntmp.DelayMetric & 0x3f)
		if !ntmp.DelayMetricSupported {
			value[i+1] |= 0x80
		}
		if ntmp.DelayMetricType == METRIC_TYPE_EXTERNAL {
			value[i+1] |= 0x40
		}
		value[i+2] = (ntmp.ExpenseMetric & 0x3f)
		if !ntmp.ExpenseMetricSupported {
			value[i+2] |= 0x80
		}
		if ntmp.ExpenseMetricType == METRIC_TYPE_EXTERNAL {
			value[i+2] |= 0x40
		}
		value[i+3] = (ntmp.ErrorMetric & 0x3f)
		if !ntmp.ErrorMetricSupported {
			value[i+3] |= 0x80
		}
		if ntmp.ErrorMetricType == METRIC_TYPE_EXTERNAL {
			value[i+3] |= 0x40
		}
		copy(value[i+4:i+4+NEIGHBOUR_ID_LENGTH], ntmp.neighbourId[0:NEIGHBOUR_ID_LENGTH])
		i += 4 + NEIGHBOUR_ID_LENGTH
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
	End System Neighbours
	code - 3
	Length - 4, plus a multiple of IDLength.
	Value -
	+------------------------+
	| Virtual Flag           | 1
	+---+---+----------------+
	| 0 |I/E| Default Metric | 1
	+---+---+----------------+
	| S |I/E| Delay Metric   | 1
	+---+---+----------------+
	| S |I/E| Expense Metric | 1
	+---+---+----------------+
	| S |I/E| Error Metric   | 1
	+---+---+----------------+
	| Neighbour ID            | ID Length
	+------------------------+
	:                        :
	:                        :
	+------------------------+
	| Neighbour ID            | ID Length
	+------------------------+
*/

/*
	Partition Designated Level 2 Intermediate System
	code - 4
	Length - IDLength
	Value -
	+------------------------+
	| Designated L2 IS ID    | ID Length
	+------------------------+
*/

type partitionDesignatedL2IsTlv struct {
	base             tlvBase
	designatedL2IsId [SYSTEM_ID_LENGTH]byte
}

func NewPartitionDesignatedL2IsTlv() (*partitionDesignatedL2IsTlv, error) {
	tlv := partitionDesignatedL2IsTlv{
		base: tlvBase{
			code: TLV_CODE_PARTITION_DESIGNATED_L2_IS,
		},
	}
	tlv.base.init()
	return &tlv, nil
}

func (tlv *partitionDesignatedL2IsTlv) SetDesignatedL2IsId(designatedL2IsId [SYSTEM_ID_LENGTH]byte) error {
	tlv.designatedL2IsId = designatedL2IsId
	return nil
}

func (tlv *partitionDesignatedL2IsTlv) TlvCode() TlvCode {
	return tlv.base.code
}

func (tlv *partitionDesignatedL2IsTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.base.String())
	fmt.Fprintf(&b, "    Designated L2 IS ID         ")
	for _, btmp := range tlv.designatedL2IsId {
		fmt.Fprintf(&b, "%02x", btmp)
	}
	fmt.Fprintf(&b, "\n")
	return b.String()
}

func (tlv *partitionDesignatedL2IsTlv) DecodeFromBytes(data []byte) error {
	err := tlv.base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	if len(tlv.base.value) != SYSTEM_ID_LENGTH {
		return errors.New("PartitionDesignatedL2IsTlv.DecodeFromBytes: value length mismatch")
	}
	copy(tlv.designatedL2IsId[0:SYSTEM_ID_LENGTH], tlv.base.value[0:SYSTEM_ID_LENGTH])
	return nil
}

func (tlv *partitionDesignatedL2IsTlv) Serialize() ([]byte, error) {
	value := make([]byte, SYSTEM_ID_LENGTH)
	copy(value[0:SYSTEM_ID_LENGTH], tlv.designatedL2IsId[0:SYSTEM_ID_LENGTH])
	tlv.base.length = SYSTEM_ID_LENGTH
	tlv.base.value = value
	data, err := tlv.base.Serialize()
	if err != nil {
		return data, err
	}
	return data, nil
}

/*
	Prefix Neighbours
	code - 5
	Length - Total length of the value field.
	Value -
	+---+---+----------------+
	| 0 |I/E| Default Metric | 1
	+---+---+----------------+
	| S |I/E| Delay Metric   | 1
	+---+---+----------------+
	| S |I/E| Expense Metric | 1
	+---+---+----------------+
	| S |I/E| Error Metric   | 1
	+---+---+----------------+
	| Address Prefix Length  | 1
	+------------------------+
	| Address Prefix         | Address Prefix Length / 2
	+------------------------+
	:                        :
	:                        :
	+------------------------+
	| Address Prefix Length  | 1
	+------------------------+
	| Address Prefix         | Address Prefix Length / 2
	+------------------------+
*/

/*
	Intermediate System Neighbours (Hellos)
	code - 6
	Length - total length of the value field in octets.
	Value -
	+------------------------+
	| LAN Address            | 6
	+------------------------+
	:                        :
	:                        :
	+------------------------+
	| LAN Address            | 6
	+------------------------+

*/

type isNeighboursHelloTlv struct {
	base         tlvBase
	lanAddresses [][SYSTEM_ID_LENGTH]byte
}

func NewIsNeighboursHelloTlv() (*isNeighboursHelloTlv, error) {
	tlv := isNeighboursHelloTlv{
		base: tlvBase{
			code: TLV_CODE_IS_NEIGHBOURS_HELLO,
		},
	}
	tlv.base.init()
	tlv.lanAddresses = make([][SYSTEM_ID_LENGTH]byte, 0)
	return &tlv, nil
}

func (tlv *isNeighboursHelloTlv) LanAddresses() [][SYSTEM_ID_LENGTH]byte {
	lanAddresses := make([][SYSTEM_ID_LENGTH]byte, 0)
	for _, latmp := range tlv.lanAddresses {
		lanAddress := latmp
		lanAddresses = append(lanAddresses, lanAddress)
	}
	return lanAddresses
}

func (tlv *isNeighboursHelloTlv) AddLanAddress(lanAddress [SYSTEM_ID_LENGTH]byte) error {
	for _, latmp := range tlv.lanAddresses {
		if bytes.Equal(lanAddress[:], latmp[:]) {
			return nil
		}
	}
	length := SYSTEM_ID_LENGTH * len(tlv.lanAddresses)
	if length+SYSTEM_ID_LENGTH > 255 {
		return errors.New("IsNeighboursHelloTlv.AddLanAddress: size over")
	}
	tlv.lanAddresses = append(tlv.lanAddresses, lanAddress)
	tlv.base.length = uint8(length + SYSTEM_ID_LENGTH)
	return nil
}

func (tlv *isNeighboursHelloTlv) RemoveLanAddress(lanAddress [SYSTEM_ID_LENGTH]byte) error {
	lanAddresses := make([][SYSTEM_ID_LENGTH]byte, 0)
	for _, latmp := range tlv.lanAddresses {
		if !bytes.Equal(lanAddress[:], latmp[:]) {
			lanAddresses = append(lanAddresses, latmp)
		}
	}
	tlv.lanAddresses = lanAddresses
	tlv.base.length = uint8(SYSTEM_ID_LENGTH * len(tlv.lanAddresses))
	return nil
}

func (tlv *isNeighboursHelloTlv) TlvCode() TlvCode {
	return tlv.base.code
}

func (tlv *isNeighboursHelloTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.base.String())
	for _, lanAddress := range tlv.lanAddresses {
		fmt.Fprintf(&b, "    LanAddress                  ")
		for _, btmp := range lanAddress {
			fmt.Fprintf(&b, "%02x", btmp)
		}
		fmt.Fprintf(&b, "\n")
	}
	return b.String()
}

func (tlv *isNeighboursHelloTlv) DecodeFromBytes(data []byte) error {
	err := tlv.base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	lanAddresses := make([][SYSTEM_ID_LENGTH]byte, 0)
	consumed := 0
	for i := 0; i < len(tlv.base.value); i += SYSTEM_ID_LENGTH {
		if i+SYSTEM_ID_LENGTH > len(tlv.base.value) {
			return errors.New("IsNeighboursHelloTlv.DecodeFromBytes: value length overflow")
		}
		var lanAddress [SYSTEM_ID_LENGTH]byte
		copy(lanAddress[0:SYSTEM_ID_LENGTH], tlv.base.value[i:i+SYSTEM_ID_LENGTH])
		lanAddresses = append(lanAddresses, lanAddress)
		consumed += SYSTEM_ID_LENGTH
	}
	if consumed != len(tlv.base.value) {
		return errors.New("IsNeighboursHelloTlv.DecodeFromBytes: value length mismatch")
	}
	tlv.lanAddresses = lanAddresses
	return nil
}

func (tlv *isNeighboursHelloTlv) Serialize() ([]byte, error) {
	length := SYSTEM_ID_LENGTH * len(tlv.lanAddresses)
	value := make([]byte, length)
	var i int
	for _, lanAddress := range tlv.lanAddresses {
		copy(value[i:i+SYSTEM_ID_LENGTH], lanAddress[0:SYSTEM_ID_LENGTH])
		i += SYSTEM_ID_LENGTH
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
	Intermediate System Neighbours (variable length)
	code - 7
	Length - Total length of the value field in octets.
	Value -
	+------------------------+
	| LAN Address Length     | 1
	+------------------------+
	| LAN Address(varlen)    | LAN Address Length
	+------------------------+
	:                        :
	:                        :
	+------------------------+
	| LAN Address(varlen)    | LAN Address Length
	+------------------------+
*/

/*
	Padding
	code - 8
	Length - Total length of the value field(may be zero).
	Value -
	+------------------------+
	| Padding                | Length
	+------------------------+
*/

type paddingTlv struct {
	base tlvBase
}

func NewPaddingTlv() (*paddingTlv, error) {
	tlv := paddingTlv{
		base: tlvBase{
			code: TLV_CODE_PADDING,
		},
	}
	tlv.base.init()
	return &tlv, nil
}

func (tlv *paddingTlv) SetLength(length uint8) error {
	value := make([]byte, length)
	tlv.base.length = length
	tlv.base.value = value
	return nil
}

func (tlv *paddingTlv) TlvCode() TlvCode {
	return tlv.base.code
}

func (tlv *paddingTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.base.String())
	return b.String()
}

func (tlv *paddingTlv) DecodeFromBytes(data []byte) error {
	err := tlv.base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	return nil
}

func (tlv *paddingTlv) Serialize() ([]byte, error) {
	tlv.base.value = make([]byte, tlv.base.length)
	data, err := tlv.base.Serialize()
	if err != nil {
		return data, err
	}
	return data, nil
}

/*
	LSP Entries
	code - 9
	Length - Total length of the value field.
	Value -
	+------------------------+
	| Remaining Lifetime     | 2
	+------------------------+
	| LSP ID                 | IDLength + 2
	+------------------------+
	| LSP Sequence Number    | 4
	+------------------------+
	| Checksum               | 2
	+------------------------+
	:                        :
	:                        :
	+------------------------+
	| Remaining Lifetime     | 2
	+------------------------+
	| LSP ID                 | IDLength + 2
	+------------------------+
	| LSP Sequence Number    | 4
	+------------------------+
	| Checksum               | 2
	+------------------------+
*/

type lspEntriesLspEntry struct {
	RemainingLifetime uint16
	lspId             [LSP_ID_LENGTH]byte
	LspSeqNum         uint32
	Checksum          uint16
}

func NewLspEntriesLspEntry(lspId [LSP_ID_LENGTH]byte) (*lspEntriesLspEntry, error) {
	lspEntry := lspEntriesLspEntry{}
	lspEntry.lspId = lspId
	return &lspEntry, nil
}

func (lspEntry *lspEntriesLspEntry) LspId() [LSP_ID_LENGTH]byte {
	return lspEntry.lspId
}

type lspEntriesTlv struct {
	base       tlvBase
	lspEntries []lspEntriesLspEntry
}

func NewLspEntriesTlv() (*lspEntriesTlv, error) {
	tlv := lspEntriesTlv{
		base: tlvBase{
			code: TLV_CODE_LSP_ENTRIES,
		},
	}
	tlv.base.init()
	tlv.lspEntries = make([]lspEntriesLspEntry, 0)
	return &tlv, nil
}

func (tlv *lspEntriesTlv) LspEntries() []lspEntriesLspEntry {
	lspEntries := make([]lspEntriesLspEntry, 0)
	for _, ltmp := range tlv.lspEntries {
		lspEntry := ltmp
		lspEntries = append(lspEntries, lspEntry)
	}
	return lspEntries
}

func (tlv *lspEntriesTlv) AddLspEntry(lspEntry *lspEntriesLspEntry) error {
	length := 0
	for _, ltmp := range tlv.lspEntries {
		if bytes.Equal(lspEntry.lspId[:], ltmp.lspId[:]) {
			return nil
		}
		length += 8 + LSP_ID_LENGTH
	}
	if length+8+LSP_ID_LENGTH > 255 {
		return errors.New("LspEntriesTlv.AddLspEntry: size over")
	}
	tlv.lspEntries = append(tlv.lspEntries, *lspEntry)
	tlv.base.length = uint8(length + 8 + LSP_ID_LENGTH)
	return nil
}

func (tlv *lspEntriesTlv) RemoveLspEntry(lspId []byte) error {
	length := 0
	lspEntries := make([]lspEntriesLspEntry, 0)
	for _, ltmp := range tlv.lspEntries {
		if !bytes.Equal(lspId[:], ltmp.lspId[:]) {
			lspEntries = append(lspEntries, ltmp)
			length += 8 + LSP_ID_LENGTH
		}
	}
	tlv.lspEntries = lspEntries
	tlv.base.length = uint8(length)
	return nil
}

func (tlv *lspEntriesTlv) TlvCode() TlvCode {
	return tlv.base.code
}

func (tlv *lspEntriesTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.base.String())
	for i, ltmp := range tlv.lspEntries {
		fmt.Fprintf(&b, "    LspEntry[%d]\n", i)
		fmt.Fprintf(&b, "        RemainingLifetime       %d\n", ltmp.RemainingLifetime)
		fmt.Fprintf(&b, "        LspId                   ")
		for _, btmp := range ltmp.lspId {
			fmt.Fprintf(&b, "%02x", btmp)
		}
		fmt.Fprintf(&b, "\n")
		fmt.Fprintf(&b, "        LspSeqNum               0x%08x\n", ltmp.LspSeqNum)
		fmt.Fprintf(&b, "        Checksum                0x%04x\n", ltmp.Checksum)
	}
	return b.String()
}

func (tlv *lspEntriesTlv) DecodeFromBytes(data []byte) error {
	err := tlv.base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	lspEntries := make([]lspEntriesLspEntry, 0)
	consumed := 0
	for i := 0; i < len(tlv.base.value); i += 8 + LSP_ID_LENGTH {
		var lspid [LSP_ID_LENGTH]byte
		copy(lspid[0:LSP_ID_LENGTH], tlv.base.value[i+2:i+2+LSP_ID_LENGTH])
		ltmp, err := NewLspEntriesLspEntry(lspid)
		if err != nil {
			return errors.New("lspEntriesTlv.DecodeFromBytes: LSP ID invalid")
		}
		ltmp.RemainingLifetime = binary.BigEndian.Uint16(tlv.base.value[i+0 : i+2])
		ltmp.LspSeqNum = binary.BigEndian.Uint32(tlv.base.value[i+2+LSP_ID_LENGTH : i+6+LSP_ID_LENGTH])
		ltmp.Checksum = binary.BigEndian.Uint16(tlv.base.value[i+6+LSP_ID_LENGTH : i+8+LSP_ID_LENGTH])
		lspEntries = append(lspEntries, *ltmp)
		consumed += 8 + LSP_ID_LENGTH
	}
	if consumed != len(tlv.base.value) {
		return errors.New("LspEntriesTlv.DecodeFromBytes: value length mismatch")
	}
	tlv.lspEntries = lspEntries
	return nil
}

func (tlv *lspEntriesTlv) Serialize() ([]byte, error) {
	length := (8 + LSP_ID_LENGTH) * len(tlv.lspEntries)
	value := make([]byte, length)
	i := 0
	for _, ltmp := range tlv.lspEntries {
		binary.BigEndian.PutUint16(value[i+0:i+2], ltmp.RemainingLifetime)
		copy(value[i+2:i+2+LSP_ID_LENGTH], ltmp.lspId[0:LSP_ID_LENGTH])
		binary.BigEndian.PutUint32(value[i+2+LSP_ID_LENGTH:i+6+LSP_ID_LENGTH], ltmp.LspSeqNum)
		binary.BigEndian.PutUint16(value[i+6+LSP_ID_LENGTH:i+8+LSP_ID_LENGTH], ltmp.Checksum)
		i += 8 + LSP_ID_LENGTH
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
	code - 10
	Length - Variable from 1-254 octets.
	Value -
	+------------------------+
	| Authentication Type    | 1
	+------------------------+
	| Authentication Value   | Variable
	+------------------------+
*/

type authInfoTlv struct {
	base      tlvBase
	AuthType  AuthType
	authValue []byte
}

func NewAuthInfoTlv() (*authInfoTlv, error) {
	tlv := authInfoTlv{
		base: tlvBase{
			code: TLV_CODE_AUTH_INFO,
		},
	}
	tlv.base.init()
	tlv.authValue = make([]byte, 0)
	return &tlv, nil
}

func (tlv *authInfoTlv) TlvCode() TlvCode {
	return tlv.base.code
}

func (tlv *authInfoTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.base.String())
	fmt.Fprintf(&b, "    AuthType                    %s\n", tlv.AuthType)
	fmt.Fprintf(&b, "    AuthValue                   ")
	for _, btmp := range tlv.authValue {
		fmt.Fprintf(&b, "%02x", btmp)
	}
	fmt.Fprintf(&b, "\n")
	return b.String()
}

func (tlv *authInfoTlv) DecodeFromBytes(data []byte) error {
	err := tlv.base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	tlv.AuthType = AuthType(tlv.base.value[0])
	authValue := make([]byte, len(tlv.base.value[1:]))
	copy(authValue, tlv.base.value[1:])
	tlv.authValue = authValue
	return nil
}

func (tlv *authInfoTlv) Serialize() ([]byte, error) {
	value := make([]byte, 1+len(tlv.authValue))
	value[0] = uint8(tlv.AuthType)
	copy(value[1:], tlv.authValue)
	tlv.base.length = uint8(len(value))
	tlv.base.value = value
	data, err := tlv.base.Serialize()
	if err != nil {
		return data, err
	}
	return data, nil
}

/*
	originatingLSPBufferSize
	code - 14
	Length - 2
	Value - 512 - 1492
	+------------------------+
	| LSPBufferSize          | 2
	+------------------------+
*/

type lspBuffSizeTlv struct {
	base          tlvBase
	LspBufferSize uint16
}

func NewLspBuffSizeTlv() (*lspBuffSizeTlv, error) {
	tlv := lspBuffSizeTlv{
		base: tlvBase{
			code: TLV_CODE_LSP_BUFF_SIZE,
		},
	}
	tlv.base.init()
	return &tlv, nil
}

func (tlv *lspBuffSizeTlv) TlvCode() TlvCode {
	return tlv.base.code
}

func (tlv *lspBuffSizeTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.base.String())
	fmt.Fprintf(&b, "    LspBufferSize               %d\n", tlv.LspBufferSize)
	return b.String()
}

func (tlv *lspBuffSizeTlv) DecodeFromBytes(data []byte) error {
	err := tlv.base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	tlv.LspBufferSize = binary.BigEndian.Uint16(tlv.base.value[0:2])
	return nil
}

func (tlv *lspBuffSizeTlv) Serialize() ([]byte, error) {
	value := make([]byte, 2)
	binary.BigEndian.PutUint16(value[0:2], tlv.LspBufferSize)
	tlv.base.length = uint8(len(value))
	tlv.base.value = value
	data, err := tlv.base.Serialize()
	if err != nil {
		return data, err
	}
	return data, nil
}
