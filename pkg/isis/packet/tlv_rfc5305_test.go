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

func TestExtendedIsReachabilityTlv(t *testing.T) {
	var err error
	p1 := []byte{0x16, 0x16,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x00, 0x00, 0x00, 0x0a, 0x00,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x00, 0x00, 0x0a, 0x00,
	}

	t1, err := NewExtendedIsReachabilityTlv()
	if err != nil {
		t.Fatalf("failed NewExtendedIsReachabilityTlv: %#v", err)
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

func TestTrafficEngineeringRouterIdTlv(t *testing.T) {
	var err error
	p1 := []byte{0x86, 0x04, 0xc0, 0xa8, 0x01, 0x01}

	t1, err := NewTrafficEngineeringRouterIdTlv()
	if err != nil {
		t.Fatalf("failed NewTrafficEngineeringRouterIdTlv: %#v", err)
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

func TestExtendedIpReachabilityTlv(t *testing.T) {
	var err error
	p1 := []byte{0x87, 0x10,
		0x00, 0x00, 0x00, 0x0a, 0x18, 0xc0, 0xa8, 0x01,
		0x00, 0x00, 0x00, 0x0a, 0x18, 0xc0, 0xa8, 0x02,
	}

	t1, err := NewExtendedIpReachabilityTlv()
	if err != nil {
		t.Fatalf("failed NewExtendedIpReachabilityTlv: %#v", err)
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
