package packet

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestIihPduP2pDecode(t *testing.T) {
	var err error

	d1 := []byte{
		0x83, 0x14, 0x01, 0x00, 0x11, 0x01, 0x00, 0x00, 0x02, 0x36, 0xd3, 0x64, 0x2f, 0x27, 0xad, 0x00, 0x1e, 0x05, 0xd9, 0x00,
		0x81, 0x02, 0xcc, 0x8e,
		0x01, 0x02, 0x01, 0x01,
		0xf0, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfa, 0xa5, 0x6c, 0xc9, 0xad, 0xad, 0x00, 0x00, 0x00, 0x00,
		0x84, 0x04, 0xc0, 0xa8, 0x0c, 0x01,
		0xe8, 0x10, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb8, 0x19, 0x81, 0xff, 0xfe, 0xa4, 0xbf, 0xd8,
		0x08, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xff, 0x02, 0x01, 0x02,
	}
	binary.BigEndian.PutUint16(d1[17:19], uint16(len(d1)))

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

func TestIihPduP2pNew(t *testing.T) {
	var err error

	p1, err := NewIihPdu(PDU_TYPE_P2P_IIHP)
	if err != nil {
		t.Fatalf("failed NewIihPdu: %#v", err)
	}

	tt, err := NewP2p3wayAdjacencyTlv()
	if err != nil {
		t.Fatalf("failed NewP2p3wayAdjacencyTlv: %#v", err)
	}
	tt.Adj3wayState = ADJ_3WAY_STATE_INITIALIZING
	xx := [SYSTEM_ID_LENGTH]byte{0x01, 0x01, 0x01, 0x02, 0x02, 0x02}
	tt.SetNeighbourSystemId(xx)
	p1.SetP2p3wayAdjacencyTlv(tt)

	//p1.ClearP2p3wayAdjacencyTlvs()

	tt2, err := NewPaddingTlv()
	if err != nil {
		t.Fatalf("failed NewPaddingTlv: %#v", err)
	}
	tt2.SetLength(8)
	p1.AddPaddingTlv(tt2)
	p1.AddPaddingTlv(tt2)

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

func TestIihPduLan2Decode(t *testing.T) {
	var err error

	d1 := []byte{
		0x83, 0x1b, 0x01, 0x00, 0x10, 0x01, 0x00, 0x00, 0x02, 0x36, 0xd3, 0x64, 0x2f, 0x27, 0xad, 0x00, 0x1e, 0x05, 0xd9, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x81, 0x02, 0xcc, 0x8e,
		0x01, 0x02, 0x01, 0x01,
		0x84, 0x04, 0xc0, 0xa8, 0x0c, 0x01,
		0xe8, 0x10, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x0e, 0x6c, 0xff, 0xfe, 0x0c, 0xef, 0xba,
		0x08, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xff, 0x02, 0x01, 0x02,
	}
	binary.BigEndian.PutUint16(d1[17:19], uint16(len(d1)))

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

func TestIihPduLan2New(t *testing.T) {
	var err error

	p1, err := NewIihPdu(PDU_TYPE_LEVEL2_LAN_IIHP)
	if err != nil {
		t.Fatalf("failed NewIihPdu: %#v", err)
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
