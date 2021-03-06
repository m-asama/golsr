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
	_ "encoding/binary"
	"testing"
)

func TestSnPduCsnpDecode(t *testing.T) {
	var err error

	d1 := []byte{
		0x83, 0x21, 0x01, 0x00, 0x19, 0x01, 0x00, 0x00, 0x00, 0x73, 0xfa, 0xa5, 0x6c, 0xc9, 0xad, 0xad, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x09, 0x50,
		0x04, 0x5e, 0x12, 0x16, 0xbb, 0x16, 0xa8, 0xe9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0xa4, 0x9b,
		0x04, 0x66, 0x36, 0xd3, 0x64, 0x2f, 0x27, 0xad, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x0b, 0xab,
		0x04, 0x75, 0x8e, 0x7f, 0x0f, 0x71, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0xe8, 0x78,
		0x04, 0x8f, 0xfa, 0xa5, 0x6c, 0xc9, 0xad, 0xad, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0xeb, 0xe9,
		0x04, 0x7f, 0xfa, 0xa5, 0x6c, 0xc9, 0xad, 0xad, 0xc4, 0x00, 0x00, 0x00, 0x00, 0x02, 0x16, 0x1d,
	}
	//binary.BigEndian.PutUint16(d1[8:10], uint16(len(d1)))

	p1, err := DecodePduFromBytes(d1)
	if err != nil {
		t.Fatalf("failed DecodePduFromBytes: %#v", err)
	}

	d2, err := p1.Serialize()
	if err != nil {
		t.Fatalf("failed Serialize: %#v", err)
	}

	if !bytes.Equal(d1, d2) {
		t.Fatalf("failed !bytes.Equal")
	}

	//t.Fatalf("\n%s", p1.String())
}

func TestSnPduCsnpNew(t *testing.T) {
	var err error

	p1, err := NewSnPdu(PDU_TYPE_LEVEL2_CSNP)
	if err != nil {
		t.Fatalf("failed NewSnPdu: %#v", err)
	}

	d1, err := p1.Serialize()
	if err != nil {
		t.Fatalf("failed Serialize: %#v", err)
	}

	p2, err := DecodePduFromBytes(d1)
	if err != nil {
		t.Fatalf("failed DecodePduFromBytes: %#v", err)
	}

	d2, err := p2.Serialize()
	if err != nil {
		t.Fatalf("failed Serialize: %#v", err)
	}

	if !bytes.Equal(d1, d2) {
		t.Fatalf("failed !bytes.Equal")
	}

	//t.Fatalf("\n%s", p1.String())
}

func TestSnPduPsnpDecode(t *testing.T) {
	var err error

	d1 := []byte{
		0x83, 0x11, 0x01, 0x00, 0x1b, 0x01, 0x00, 0x00, 0x00, 0x23, 0x36, 0xd3, 0x64, 0x2f, 0x27, 0xad, 0x00,
		0x09, 0x10,
		0x04, 0x8d, 0xfa, 0xa5, 0x6c, 0xc9, 0xad, 0xad, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x3a, 0xb8,
	}
	//binary.BigEndian.PutUint16(d1[8:10], uint16(len(d1)))

	p1, err := DecodePduFromBytes(d1)
	if err != nil {
		t.Fatalf("failed DecodePduFromBytes: %#v", err)
	}

	d2, err := p1.Serialize()
	if err != nil {
		t.Fatalf("failed Serialize: %#v", err)
	}

	if !bytes.Equal(d1, d2) {
		t.Fatalf("failed !bytes.Equal")
	}

	//t.Fatalf("\n%s", p1.String())
}

func TestSnPduPsnpNew(t *testing.T) {
	var err error

	p1, err := NewSnPdu(PDU_TYPE_LEVEL2_PSNP)
	if err != nil {
		t.Fatalf("failed NewSnPdu: %#v", err)
	}

	d1, err := p1.Serialize()
	if err != nil {
		t.Fatalf("failed Serialize: %#v", err)
	}

	p2, err := DecodePduFromBytes(d1)
	if err != nil {
		t.Fatalf("failed DecodePduFromBytes: %#v", err)
	}

	d2, err := p2.Serialize()
	if err != nil {
		t.Fatalf("failed Serialize: %#v", err)
	}

	if !bytes.Equal(d1, d2) {
		t.Fatalf("failed !bytes.Equal")
	}

	//t.Fatalf("\n%s", p1.String())
}
