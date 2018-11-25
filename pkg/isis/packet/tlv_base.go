package packet

import (
	"bytes"
	"errors"
	"fmt"
)

type tlvBase struct {
	code   TlvCode
	length uint8
	value  []byte
}

func (base *tlvBase) init() {
	base.value = make([]byte, 0)
}

func (base *tlvBase) String() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "    code                %s(%d)\n", base.code.String(), base.code)
	fmt.Fprintf(&b, "    Length              %d\n", base.length)
	fmt.Fprintf(&b, "    Value              ")
	for i := 0; i < len(base.value); i++ {
		if i > 0 && i%20 == 0 {
			fmt.Fprintf(&b, "\n                       ")
		}
		fmt.Fprintf(&b, " %02x", base.value[i])
	}
	fmt.Fprintf(&b, "\n")
	return b.String()
}

func (base *tlvBase) DecodeFromBytes(data []byte) error {
	if len(data) < 2 {
		return errors.New("tlvBase.DecodeFromBytes: data length too short")
	}
	base.code = TlvCode(data[0])
	base.length = data[1]
	if len(data) != int(base.length+2) {
		return errors.New("tlvBase.DecodeFromBytes: data length mismatch")
	}
	base.value = make([]byte, len(data)-2)
	copy(base.value, data[2:])
	return nil
}

func (base *tlvBase) Serialize() ([]byte, error) {
	if len(base.value) != int(base.length) {
		return nil, errors.New("tlvBase.Serialize: value length mismatch")
	}
	data := make([]byte, base.length+2)
	data[0] = uint8(base.code)
	data[1] = base.length
	copy(data[2:], base.value)
	return data, nil
}

func DecodeTlvFromBytes(data []byte) (IsisTlv, error) {
	var tlv IsisTlv
	var err error
	if len(data) < 2 {
		return nil, errors.New("DecodeTlvFromBytes: data length too short")
	}
	code := TlvCode(data[0])
	switch code {
	case TLV_CODE_AREA_ADDRESSES:
		tlv, err = NewAreaAddressesTlv()
	case TLV_CODE_IS_NEIGHBOURS_LSP:
		tlv, err = NewIsNeighboursLspTlv()
		/*
			case TLV_CODE_ES_NEIGHBOURS:
				tlv, err = NewEsNeighboursTlv()
		*/
	case TLV_CODE_PARTITION_DESIGNATED_L2_IS:
		tlv, err = NewPartitionDesignatedL2IsTlv()
		/*
			case TLV_CODE_PREFIX_NEIGHBOURS:
				tlv, err = NewPrefixNeighboursTlv()
		*/
	case TLV_CODE_IS_NEIGHBOURS_HELLO:
		tlv, err = NewIsNeighboursHelloTlv()
		/*
			case TLV_CODE_IS_NEIGHBOURS_VARIABLE:
				tlv, err = NewIsNeighboursVariableTlv()
		*/
	case TLV_CODE_PADDING:
		tlv, err = NewPaddingTlv()
	case TLV_CODE_ESP_ENTRIES:
		tlv, err = NewLspEntriesTlv()
	case TLV_CODE_AUTH_INFO:
		tlv, err = NewAuthInfoTlv()
	case TLV_CODE_LSP_BUFF_SIZE:
		tlv, err = NewLspBuffSizeTlv()
	default:
		tlv, err = NewUnknownTlv(code)
	}
	if err != nil {
		return nil, err
	}
	err = tlv.DecodeFromBytes(data)
	if err != nil {
		return nil, err
	}
	return tlv, nil
}

type unknownTlv struct {
	base tlvBase
}

func NewUnknownTlv(code TlvCode) (*unknownTlv, error) {
	tlv := unknownTlv{
		base: tlvBase{
			code: code,
		},
	}
	tlv.base.init()
	return &tlv, nil
}

func (tlv *unknownTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.base.String())
	return b.String()
}

func (tlv *unknownTlv) DecodeFromBytes(data []byte) error {
	err := tlv.base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	return nil
}

func (tlv *unknownTlv) Serialize() ([]byte, error) {
	data, err := tlv.base.Serialize()
	if err != nil {
		return data, err
	}
	return data, nil
}
