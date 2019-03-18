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
	Point-to-Point Three-Way Adjacency
	code - 240
	Length -
	Value -
	+------------------------+
	| AdjacencyThreeWayState | 1
	+------------------------+
	| ExtendedLocalCircuitID | 4
	+------------------------+
	| Neighbour System ID    | ID Length
	+------------------------+
	| NeighExtLocalCircuitID | 4
	+------------------------+
*/

type p2p3wayAdjacencyTlv struct {
	base                   tlvBase
	Adj3wayState           Adj3wayState
	ExtLocalCircuitId      uint32
	neighbourSystemId      [SYSTEM_ID_LENGTH]byte
	NeighExtLocalCircuitId uint32
}

func NewP2p3wayAdjacencyTlv() (*p2p3wayAdjacencyTlv, error) {
	tlv := p2p3wayAdjacencyTlv{
		base: tlvBase{
			code: TLV_CODE_P2P_3WAY_ADJ,
		},
	}
	tlv.base.init()
	return &tlv, nil
}

func (tlv *p2p3wayAdjacencyTlv) SetNeighbourSystemId(neighbourSystemId [SYSTEM_ID_LENGTH]byte) error {
	tlv.neighbourSystemId = neighbourSystemId
	tlv.base.length = 9 + SYSTEM_ID_LENGTH
	return nil
}

func (tlv *p2p3wayAdjacencyTlv) TlvCode() TlvCode {
	return tlv.base.code
}

func (tlv *p2p3wayAdjacencyTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.base.String())
	fmt.Fprintf(&b, "    AdjThreeWayState            %s\n", tlv.Adj3wayState)
	fmt.Fprintf(&b, "    ExtLocalCircuitID           0x%08x\n", tlv.ExtLocalCircuitId)
	fmt.Fprintf(&b, "    NeighbourSystemID           ")
	for _, btmp := range tlv.neighbourSystemId {
		fmt.Fprintf(&b, "%02x", btmp)
	}
	fmt.Fprintf(&b, "\n")
	fmt.Fprintf(&b, "    NeighExtLocalCircID         0x%08x\n", tlv.NeighExtLocalCircuitId)
	return b.String()
}

func (tlv *p2p3wayAdjacencyTlv) DecodeFromBytes(data []byte) error {
	err := tlv.base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	tlv.Adj3wayState = Adj3wayState(tlv.base.value[0])
	tlv.ExtLocalCircuitId = 0
	if len(tlv.base.value) > 1 {
		if len(tlv.base.value) < 5 {
			return errors.New("P2p3wayAdjacencyTlv.DecodeFromBytes: length invalid")
		}
		tlv.ExtLocalCircuitId = binary.BigEndian.Uint32(tlv.base.value[1:5])
	}
	if len(tlv.base.value) > 5 {
		if len(tlv.base.value) < 5+SYSTEM_ID_LENGTH {
			return errors.New("P2p3wayAdjacencyTlv.DecodeFromBytes: length invalid")
		}
		copy(tlv.neighbourSystemId[0:SYSTEM_ID_LENGTH], tlv.base.value[5:5+SYSTEM_ID_LENGTH])
	}
	tlv.NeighExtLocalCircuitId = 0
	if len(tlv.base.value) > 5+SYSTEM_ID_LENGTH {
		if len(tlv.base.value) < 9+SYSTEM_ID_LENGTH {
			return errors.New("P2p3wayAdjacencyTlv.DecodeFromBytes: length invalid")
		}
		tlv.NeighExtLocalCircuitId = binary.BigEndian.Uint32(tlv.base.value[5+SYSTEM_ID_LENGTH : 9+SYSTEM_ID_LENGTH])
	}
	return nil
}

func (tlv *p2p3wayAdjacencyTlv) Serialize() ([]byte, error) {
	length := 5
	if tlv.Adj3wayState != ADJ_3WAY_STATE_DOWN {
		length = 9 + SYSTEM_ID_LENGTH
	}
	value := make([]byte, length)
	value[0] = uint8(tlv.Adj3wayState)
	binary.BigEndian.PutUint32(value[1:5], tlv.ExtLocalCircuitId)
	if tlv.Adj3wayState != ADJ_3WAY_STATE_DOWN {
		if len(tlv.neighbourSystemId) != SYSTEM_ID_LENGTH {
			xx := fmt.Sprint("P2p3wayAdjacencyTlv.Serialize: NeighbourSystemId length invalid", len(tlv.neighbourSystemId), SYSTEM_ID_LENGTH)
			return nil, errors.New(xx)
		}
		copy(value[5:5+SYSTEM_ID_LENGTH], tlv.neighbourSystemId[0:SYSTEM_ID_LENGTH])
		binary.BigEndian.PutUint32(value[5+SYSTEM_ID_LENGTH:9+SYSTEM_ID_LENGTH], tlv.NeighExtLocalCircuitId)
	}
	tlv.base.length = uint8(length)
	tlv.base.value = value
	data, err := tlv.base.Serialize()
	if err != nil {
		return data, err
	}
	return data, nil
}
