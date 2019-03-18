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
	"testing"
)

func TestIpInternalReachInfoTlv(t *testing.T) {
	var err error
	p1 := []byte{0x80, 0x18,
		0x0a, 0x80, 0x80, 0x80, 0xc0, 0xa8, 0x01, 0x00, 0xff, 0xff, 0xff, 0x00,
		0x0a, 0x80, 0x80, 0x80, 0xac, 0x10, 0x01, 0x00, 0xff, 0xff, 0xff, 0x00,
	}

	t1, err := NewIpInternalReachInfoTlv()
	if err != nil {
		t.Fatalf("failed NewIpInternalReachInfoTlv: %#v", err)
	}

	err = t1.DecodeFromBytes(p1)
	if err != nil {
		t.Fatalf("failed DecodeFromBytes: %#v", err)
	}

	p2, err := t1.Serialize()
	if err != nil {
		t.Fatalf("failed Serialize: %#v", err)
	}

	if !bytes.Equal(p1, p2) {
		t.Fatalf("failed !Equal")
	}
}

func TestProtocolsSupportedTlv(t *testing.T) {
	var err error
	p1 := []byte{0x81, 0x02, 0xcc, 0x8e}

	t1, err := NewProtocolsSupportedTlv()
	if err != nil {
		t.Fatalf("failed NewProtocolsSupportedTlv: %#v", err)
	}

	err = t1.DecodeFromBytes(p1)
	if err != nil {
		t.Fatalf("failed DecodeFromBytes: %#v", err)
	}

	p2, err := t1.Serialize()
	if err != nil {
		t.Fatalf("failed Serialize: %#v", err)
	}

	if !bytes.Equal(p1, p2) {
		t.Fatalf("failed !Equal")
	}
}

func TestIpExternalReachInfoTlv(t *testing.T) {
	var err error
	p1 := []byte{0x82, 0x18,
		0x0a, 0x80, 0x80, 0x80, 0xc0, 0xa8, 0x01, 0x00, 0xff, 0xff, 0xff, 0x00,
		0x0a, 0x80, 0x80, 0x80, 0xac, 0x10, 0x01, 0x00, 0xff, 0xff, 0xff, 0x00,
	}

	t1, err := NewIpExternalReachInfoTlv()
	if err != nil {
		t.Fatalf("failed NewIpExternalReachInfoTlv: %#v", err)
	}

	err = t1.DecodeFromBytes(p1)
	if err != nil {
		t.Fatalf("failed DecodeFromBytes: %#v", err)
	}

	p2, err := t1.Serialize()
	if err != nil {
		t.Fatalf("failed Serialize: %#v", err)
	}

	if !bytes.Equal(p1, p2) {
		t.Fatalf("failed !Equal")
	}
}

func TestInterDomainRoutingProtoInfoTlv(t *testing.T) {
	var err error
	p1 := []byte{0x83, 0x04, 0x01, 0x02, 0x03, 0x04}

	t1, err := NewInterDomainRoutingProtoInfoTlv()
	if err != nil {
		t.Fatalf("failed NewInterDomainRoutingProtoInfoTlv: %#v", err)
	}

	err = t1.DecodeFromBytes(p1)
	if err != nil {
		t.Fatalf("failed DecodeFromBytes: %#v", err)
	}

	p2, err := t1.Serialize()
	if err != nil {
		t.Fatalf("failed Serialize: %#v", err)
	}

	if !bytes.Equal(p1, p2) {
		t.Fatalf("failed !Equal")
	}
}

func TestIpInterfaceAddressTlv(t *testing.T) {
	var err error
	p1 := []byte{0x84, 0x08, 0xc0, 0xa8, 0x01, 0x01, 0xac, 0x10, 0x01, 0x01}

	t1, err := NewIpInterfaceAddressTlv()
	if err != nil {
		t.Fatalf("failed NewIpInterfaceAddressTlv: %#v", err)
	}

	err = t1.DecodeFromBytes(p1)
	if err != nil {
		t.Fatalf("failed DecodeFromBytes: %#v", err)
	}

	p2, err := t1.Serialize()
	if err != nil {
		t.Fatalf("failed Serialize: %#v", err)
	}

	if !bytes.Equal(p1, p2) {
		t.Fatalf("failed !Equal")
	}
}
