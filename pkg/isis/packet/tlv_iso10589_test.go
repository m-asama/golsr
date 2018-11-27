package packet

import (
	"bytes"
	"testing"
)

func TestAreaAddressesTlv(t *testing.T) {
	var err error
	p1 := []byte{0x01, 0x08, 0x02, 0x0a, 0x0b, 0x04, 0x01, 0x02, 0x03, 0x04}

	t1, err := NewAreaAddressesTlv()
	if err != nil {
		t.Fatalf("failed NewAreaAddressesTlv: %#v", err)
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

	err = t1.AddAreaAddress([]byte{0xaa, 0xbb})
	if err != nil {
		t.Fatalf("failed AddAreaAddress: %#v", err)
	}

	p3, err := t1.Serialize()
	if err != nil {
		t.Fatalf("failed Serialize: %#v", err)
	}

	if bytes.Equal(p1, p3) {
		t.Fatalf("failed Equal")
	}

	err = t1.RemoveAreaAddress([]byte{0xaa, 0xbb})
	if err != nil {
		t.Fatalf("failed RemoveAddress: %#v", err)
	}

	p4, err := t1.Serialize()
	if err != nil {
		t.Fatalf("failed Serialize: %#v", err)
	}

	if !bytes.Equal(p1, p4) {
		t.Fatalf("failed !Equal")
	}
}

func TestIsNeighboursLspTlv(t *testing.T) {
	var err error
	p1 := []byte{0x02, 0x17, 0x00,
		0x0a, 0x80, 0x80, 0x80, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x0a, 0x80, 0x80, 0x80, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
	}

	t1, err := NewIsNeighboursLspTlv()
	if err != nil {
		t.Fatalf("failed NewIsNeighboursLspTlv: %#v", err)
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

	n1, err := NewIsNeighboursLspNeighbour([]byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa})
	if err != nil {
		t.Fatalf("failed NewIsNeighboursLspNeighbour: %#v", err)
	}

	n1.DefaultMetric = 20
	err = t1.AddNeighbour(n1)
	if err != nil {
		t.Fatalf("failed AddNeighbour: %#v", err)
	}

	p3, err := t1.Serialize()
	if err != nil {
		t.Fatalf("failed Serialize: %#v", err)
	}

	if bytes.Equal(p1, p3) {
		t.Fatalf("failed !Equal")
	}

	err = t1.RemoveNeighbour([]byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa})
	if err != nil {
		t.Fatalf("failed RemoveNeighbour:  %#v", err)
	}

	p4, err := t1.Serialize()
	if err != nil {
		t.Fatalf("failed Serialize: %#v", err)
	}
	if !bytes.Equal(p1, p4) {
		t.Fatalf("failed !Equal")
	}

	t1.VirtualFlag = true
	p5, err := t1.Serialize()
	if err != nil {
		t.Fatalf("failed Serialize: %#v", err)
	}
	if bytes.Equal(p1, p5) {
		t.Fatalf("failed !Equal")
	}

	t1.VirtualFlag = false
	p6, err := t1.Serialize()
	if err != nil {
		t.Fatalf("failed Serialize: %#v", err)
	}
	if !bytes.Equal(p1, p6) {
		t.Fatalf("failed !Equal")
	}

	n2, err := NewIsNeighboursLspNeighbour([]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00})
	if err != nil {
		t.Fatalf("failed RemoveNeighbour:  %#v", err)
	}

	n2.DefaultMetric = 20

	err = t1.RemoveNeighbour([]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00})
	if err != nil {
		t.Fatalf("failed RemoveNeighbour:  %#v", err)
	}

	err = t1.AddNeighbour(n2)
	if err != nil {
		t.Fatalf("failed AddNeighbour: %#v", err)
	}

	p7, err := t1.Serialize()
	if err != nil {
		t.Fatalf("failed Serialize: %#v", err)
	}

	if bytes.Equal(p1, p7) {
		t.Fatalf("failed Equal: \n%x\n%x", p1, p7)
	}
}

func TestPartitionDesignatedL2IsTlv(t *testing.T) {
	var err error
	p1 := []byte{0x04, 0x06, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	t1, err := NewPartitionDesignatedL2IsTlv()
	if err != nil {
		t.Fatalf("failed NewPartitionDesignatedL2IsTlv: %#v", err)
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

	err = t1.SetDesignatedL2IsId([]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x00})
	if err != nil {
		t.Fatalf("failed SetDesignatedL2IsId: %#v", err)
	}

	p3, err := t1.Serialize()
	if err != nil {
		t.Fatalf("failed Serialize: %#v", err)
	}

	if bytes.Equal(p1, p3) {
		t.Fatalf("failed Equal")
	}
}

func TestIsNeighboursHelloTlv(t *testing.T) {
	var err error
	p1 := []byte{0x06, 0x0c,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
	}

	t1, err := NewIsNeighboursHelloTlv()
	if err != nil {
		t.Fatalf("failed NewIsNeighboursHelloTlv: %#v", err)
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

func TestPaddingTlv(t *testing.T) {
	var err error
	p1 := []byte{0x08, 0x04, 0x00, 0x00, 0x00, 0x00}

	t1, err := NewPaddingTlv()
	if err != nil {
		t.Fatalf("failed NewPaddingTlv: %#v", err)
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

	t1.SetLength(10)

	p3, err := t1.Serialize()
	if err != nil {
		t.Fatalf("failed Serialize: %#v", err)
	}

	if len(p3) != 12 {
		t.Fatalf("failed len(p3) != 12")
	}
}

func TestLspEntriesTlv(t *testing.T) {
	var err error
	p1 := []byte{0x09, 0x10,
		0x04, 0x8d, 0xfa, 0xa5, 0x6c, 0xc9, 0xad, 0xad,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x3a, 0xb8,
	}

	t1, err := NewLspEntriesTlv()
	if err != nil {
		t.Fatalf("failed NewLspEntriesTlv: %#v", err)
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
		t.Fatalf("failed !Equal:\n%x\n%x", p1, p2)
	}
}

func TestAuthInfoTlv(t *testing.T) {
	var err error
	p1 := []byte{0x0a, 0x09,
		0x01, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64}

	t1, err := NewAuthInfoTlv()
	if err != nil {
		t.Fatalf("failed NewAuthInfoTlv: %#v", err)
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
		t.Fatalf("failed !Equal:\n%x\n%x", p1, p2)
	}
}

func TestLspBuffSizeTlv(t *testing.T) {
	var err error
	p1 := []byte{0x0e, 0x02, 0xd4, 0x05}

	t1, err := NewLspBuffSizeTlv()
	if err != nil {
		t.Fatalf("failed NewLspBuffSizeTlv: %#v", err)
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
		t.Fatalf("failed !Equal:\n%x\n%x", p1, p2)
	}
}
