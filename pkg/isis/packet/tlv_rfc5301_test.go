package packet

import (
	"bytes"
	"testing"
)

func TestDynamicHostnameTlv(t *testing.T) {
	var err error
	p1 := []byte{0x89, 0x04, 0x74, 0x65, 0x73, 0x74}

	t1, err := NewDynamicHostnameTlv()
	if err != nil {
		t.Fatalf("failed NewDynamicHostnameTlv: %#v", err)
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
