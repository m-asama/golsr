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
	"fmt"
)

/*
	Dynamic hostname
	code - 137
	Length -
	Value -
	+------------------------+
	| Dynamic Hostname       |
	+------------------------+
*/

type dynamicHostnameTlv struct {
	base            tlvBase
	dynamicHostname []byte
}

func NewDynamicHostnameTlv() (*dynamicHostnameTlv, error) {
	tlv := dynamicHostnameTlv{
		base: tlvBase{
			code: TLV_CODE_DYNAMIC_HOSTNAME,
		},
	}
	tlv.base.init()
	tlv.dynamicHostname = make([]byte, 0)
	return &tlv, nil
}

func (tlv *dynamicHostnameTlv) SetDynamicHostname(dynamicHostname []byte) error {
	dhtmp := make([]byte, len(dynamicHostname))
	copy(dhtmp, dynamicHostname)
	tlv.dynamicHostname = dhtmp
	tlv.base.length = uint8(len(dhtmp))
	return nil
}

func (tlv *dynamicHostnameTlv) TlvCode() TlvCode {
	return tlv.base.code
}

func (tlv *dynamicHostnameTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.base.String())
	fmt.Fprintf(&b, "    DynamicHostname             ")
	for _, btmp := range tlv.dynamicHostname {
		fmt.Fprintf(&b, "%02x", btmp)
	}
	fmt.Fprintf(&b, "\n")
	return b.String()
}

func (tlv *dynamicHostnameTlv) DecodeFromBytes(data []byte) error {
	err := tlv.base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	dynamicHostname := make([]byte, len(tlv.base.value))
	copy(dynamicHostname, tlv.base.value)
	tlv.dynamicHostname = dynamicHostname
	return nil
}

func (tlv *dynamicHostnameTlv) Serialize() ([]byte, error) {
	value := make([]byte, len(tlv.dynamicHostname))
	copy(value, tlv.dynamicHostname)
	tlv.base.length = uint8(len(value))
	tlv.base.value = value
	data, err := tlv.base.Serialize()
	if err != nil {
		return data, err
	}
	return data, nil
}
