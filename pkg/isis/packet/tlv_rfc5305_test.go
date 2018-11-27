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
