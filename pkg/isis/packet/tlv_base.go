package packet

import (
	"bytes"
	"errors"
	"fmt"
)

type tlvBase struct {
	Code   TlvCode
	Length uint8
	Value  []byte
}

func (base *tlvBase) Init() {
	base.Value = make([]byte, 0)
}

func (base *tlvBase) String() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "    Code                %s(%d)\n", base.Code.String(), base.Code)
	fmt.Fprintf(&b, "    Length              %d\n", base.Length)
	fmt.Fprintf(&b, "    Value              ")
	for i := 0; i < len(base.Value); i++ {
		if i > 0 && i%20 == 0 {
			fmt.Fprintf(&b, "\n                       ")
		}
		fmt.Fprintf(&b, " %02x", base.Value[i])
	}
	fmt.Fprintf(&b, "\n")
	return b.String()
}

func (base *tlvBase) DecodeFromBytes(data []byte) error {
	if len(data) < 2 {
		return errors.New("tlvBase.DecodeFromBytes: data length too short")
	}
	base.Code = TlvCode(data[0])
	base.Length = data[1]
	if len(data) != int(base.Length+2) {
		return errors.New("tlvBase.DecodeFromBytes: data length mismatch")
	}
	base.Value = make([]byte, len(data)-2)
	copy(base.Value, data[2:])
	return nil
}

func (base *tlvBase) Serialize() ([]byte, error) {
	if len(base.Value) != int(base.Length) {
		return nil, errors.New("tlvBase.Serialize: value length mismatch")
	}
	data := make([]byte, base.Length+2)
	data[0] = uint8(base.Code)
	data[1] = base.Length
	copy(data[2:], base.Value)
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
		tlv, err = NewunknownTlv(code)
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
	Base tlvBase
}

func NewunknownTlv(code TlvCode) (*unknownTlv, error) {
	tlv := unknownTlv{
		Base: tlvBase{
			Code: code,
		},
	}
	tlv.Base.Init()
	return &tlv, nil
}

func (tlv *unknownTlv) String() string {
	var b bytes.Buffer
	b.WriteString(tlv.Base.String())
	return b.String()
}

func (tlv *unknownTlv) DecodeFromBytes(data []byte) error {
	err := tlv.Base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	return nil
}

func (tlv *unknownTlv) Serialize() ([]byte, error) {
	data, err := tlv.Base.Serialize()
	if err != nil {
		return data, err
	}
	return data, nil
}
