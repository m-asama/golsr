package packet

import (
	"bytes"
	"testing"
)

func TestIpv6ReachabilityTlv(t *testing.T) {
	var err error
	p1 := []byte{0xec, 0x1c,
		0x00, 0x00, 0x00, 0x0a, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x0a, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x02,
	}

	t1, err := NewIpv6ReachabilityTlv()
	if err != nil {
		t.Fatalf("failed NewIpv6ReachabilityTlv: %#v", err)
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

func TestIpv6InterfaceAddressTlv(t *testing.T) {
	var err error
	p1 := []byte{0xe8, 0x20,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}

	t1, err := NewIpv6InterfaceAddressTlv()
	if err != nil {
		t.Fatalf("failed NewIpv6InterfaceAddressTlv: %#v", err)
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
