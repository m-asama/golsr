package packet

import (
	"bytes"
	"fmt"
)

/*
	Dynamic hostname
	Code - 137
	Length -
	Value -
	+------------------------+
	| Dynamic Hostname       |
	+------------------------+
*/

type dynamicHostnameTlv struct {
	Base            tlvBase
	dynamicHostname []byte
}

func NewDynamicHostnameTlv() (*dynamicHostnameTlv, error) {
	tlv := dynamicHostnameTlv{
		Base: tlvBase{
			Code: TLV_CODE_DYNAMIC_HOSTNAME,
		},
	}
	tlv.Base.Init()
	tlv.dynamicHostname = make([]byte, 0)
	return &tlv, nil
}

func (tlv *dynamicHostnameTlv) SetDynamicHostname(dynamicHostname []byte) error {
	dhtmp := make([]byte, len(dynamicHostname))
	copy(dhtmp, dynamicHostname)
	tlv.dynamicHostname = dhtmp
	tlv.Base.Length = uint8(len(dhtmp))
	return nil
}

func (tlv *dynamicHostnameTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.Base.String())
	fmt.Fprintf(&b, "    DynamicHostname     ")
	for _, btmp := range tlv.dynamicHostname {
		fmt.Fprintf(&b, "%02x", btmp)
	}
	fmt.Fprintf(&b, "\n")
	return b.String()
}

func (tlv *dynamicHostnameTlv) DecodeFromBytes(data []byte) error {
	err := tlv.Base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	dynamicHostname := make([]byte, len(tlv.Base.Value))
	copy(dynamicHostname, tlv.Base.Value)
	tlv.dynamicHostname = dynamicHostname
	return nil
}

func (tlv *dynamicHostnameTlv) Serialize() ([]byte, error) {
	value := make([]byte, len(tlv.dynamicHostname))
	copy(value, tlv.dynamicHostname)
	tlv.Base.Length = uint8(len(value))
	tlv.Base.Value = value
	data, err := tlv.Base.Serialize()
	if err != nil {
		return data, err
	}
	return data, nil
}
