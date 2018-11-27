package packet

import (
	"bytes"
	"fmt"
)

/*
	Dynamic hostname
	code - 137
	Length -
	Value -
	+------------------------+
	| Dynamic Hostname       |
	+------------------------+
*/

type dynamicHostnameTlv struct {
	base            tlvBase
	dynamicHostname []byte
}

func NewDynamicHostnameTlv() (*dynamicHostnameTlv, error) {
	tlv := dynamicHostnameTlv{
		base: tlvBase{
			code: TLV_CODE_DYNAMIC_HOSTNAME,
		},
	}
	tlv.base.init()
	tlv.dynamicHostname = make([]byte, 0)
	return &tlv, nil
}

func (tlv *dynamicHostnameTlv) SetDynamicHostname(dynamicHostname []byte) error {
	dhtmp := make([]byte, len(dynamicHostname))
	copy(dhtmp, dynamicHostname)
	tlv.dynamicHostname = dhtmp
	tlv.base.length = uint8(len(dhtmp))
	return nil
}

func (tlv *dynamicHostnameTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.base.String())
	fmt.Fprintf(&b, "    DynamicHostname             ")
	for _, btmp := range tlv.dynamicHostname {
		fmt.Fprintf(&b, "%02x", btmp)
	}
	fmt.Fprintf(&b, "\n")
	return b.String()
}

func (tlv *dynamicHostnameTlv) DecodeFromBytes(data []byte) error {
	err := tlv.base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	dynamicHostname := make([]byte, len(tlv.base.value))
	copy(dynamicHostname, tlv.base.value)
	tlv.dynamicHostname = dynamicHostname
	return nil
}

func (tlv *dynamicHostnameTlv) Serialize() ([]byte, error) {
	value := make([]byte, len(tlv.dynamicHostname))
	copy(value, tlv.dynamicHostname)
	tlv.base.length = uint8(len(value))
	tlv.base.value = value
	data, err := tlv.base.Serialize()
	if err != nil {
		return data, err
	}
	return data, nil
}
