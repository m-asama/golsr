package packet

import (
	"bytes"
	"testing"
)

func TestP2p3wayAdjacencyTlv(t *testing.T) {
	var err error

	p1 := []byte{0xf0, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00}

	t1, err := NewP2p3wayAdjacencyTlv()
	if err != nil {
		t.Fatalf("failed NewP2p3wayAdjacencyTlv: %#v", err)
	}

	err = t1.DecodeFromBytes(p1)
	if err != nil {
		t.Fatalf("failed DecodeFromBytes: %#v", err)
	}

	p2, err := t1.Serialize()
	if err != nil {
		t.Fatalf("failed Serialize: %#v\n%x", err, p2)
	}

	if !bytes.Equal(p1, p2) {
		t.Fatalf("failed !Equal")
	}

	p3 := []byte{0xf0, 0x0f,
		0x00, 0x00, 0x00, 0x00, 0x00,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x00, 0x00, 0x00, 0x00,
	}

	t2, err := NewP2p3wayAdjacencyTlv()
	if err != nil {
		t.Fatalf("failed NewP2p3wayAdjacencyTlv: %#v", err)
	}

	err = t2.DecodeFromBytes(p3)
	if err != nil {
		t.Fatalf("failed DecodeFromBytes: %#v", err)
	}

	p4, err := t2.Serialize()
	if err != nil {
		t.Fatalf("failed Serialize: %#v\n%x", err, p4)
	}

	if !bytes.Equal(p3, p4) {
		t.Fatalf("failed !Equal")
	}

}
