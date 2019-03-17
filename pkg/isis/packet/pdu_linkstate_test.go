package packet

import (
	"bytes"
	_ "encoding/binary"
	"testing"
)

func TestLsPduDecode(t *testing.T) {
	var err error

	d1 := []byte{
		0x83, 0x1b, 0x01, 0x00, 0x14, 0x01, 0x00, 0x00, 0x00, 0x97, 0x04, 0x8b, 0x8e, 0x7f, 0x0f, 0x71, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0xc5, 0x13, 0x03,
		0x81, 0x02, 0xcc, 0x8e,
		0x01, 0x02, 0x01, 0x01,
		0x89, 0x08, 0x66, 0x72, 0x72, 0x74, 0x65, 0x73, 0x74, 0x33,
		0x86, 0x04, 0xc0, 0xa8, 0x03, 0x01,
		0x16, 0x16, 0x36, 0xd3, 0x64, 0x2f, 0x27, 0xad, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x12, 0x16, 0xbb, 0x16, 0xa8, 0xe9, 0x00, 0x00, 0x00, 0x0a, 0x00,
		0x84, 0x04, 0xc0, 0xa8, 0x03, 0x01,
		0x87, 0x18, 0x00, 0x00, 0x00, 0x0a, 0x18, 0xc0, 0xa8, 0x0d, 0x00, 0x00, 0x00, 0x0a, 0x18, 0xc0, 0xa8, 0x22, 0x00, 0x00, 0x00, 0x0a, 0x18, 0xc0, 0xa8, 0x03,
		0xec, 0x2a, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x03,
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

func TestLsPduNew(t *testing.T) {
	var err error

	p1, err := NewLsPdu(PDU_TYPE_LEVEL2_LSP)
	if err != nil {
		t.Fatalf("failed NewLsPdu: %#v", err)
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