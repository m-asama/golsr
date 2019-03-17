package packet

import (
	"bytes"
	"errors"
	"fmt"
)

type SnPdu struct {
	base pduBase

	sourceId   [NEIGHBOUR_ID_LENGTH]byte
	startLspId [LSP_ID_LENGTH]byte // CSN
	endLspId   [LSP_ID_LENGTH]byte // CSN
}

func NewSnPdu(pduType PduType) (*SnPdu, error) {
	if pduType != PDU_TYPE_LEVEL1_CSNP &&
		pduType != PDU_TYPE_LEVEL2_CSNP &&
		pduType != PDU_TYPE_LEVEL1_PSNP &&
		pduType != PDU_TYPE_LEVEL2_PSNP {
		return nil, errors.New("NewSnPdu: pduType invalid")
	}
	var lengthIndicator uint8
	switch pduType {
	case PDU_TYPE_LEVEL1_CSNP, PDU_TYPE_LEVEL2_CSNP:
		lengthIndicator = 15 + SYSTEM_ID_LENGTH*3
	case PDU_TYPE_LEVEL1_PSNP, PDU_TYPE_LEVEL2_PSNP:
		lengthIndicator = 11 + SYSTEM_ID_LENGTH
	}
	sn := SnPdu{
		base: pduBase{
			lengthIndicator: lengthIndicator,
			pduType:         pduType,
		},
	}
	sn.base.init()
	return &sn, nil
}

func (sn *SnPdu) PduType() PduType {
	return sn.base.pduType
}

func (sn *SnPdu) String() string {
	var b bytes.Buffer
	b.WriteString(sn.base.StringFixed())
	fmt.Fprintf(&b, "sourceId                        ")
	for t := range sn.sourceId {
		fmt.Fprintf(&b, "%02x", t)
	}
	fmt.Fprintf(&b, "\n")
	if sn.base.pduType == PDU_TYPE_LEVEL1_CSNP ||
		sn.base.pduType == PDU_TYPE_LEVEL2_CSNP {
		fmt.Fprintf(&b, "startLspId                      ")
		for t := range sn.startLspId {
			fmt.Fprintf(&b, "%02x", t)
		}
		fmt.Fprintf(&b, "\n")
		fmt.Fprintf(&b, "endLspId                        ")
		for t := range sn.endLspId {
			fmt.Fprintf(&b, "%02x", t)
		}
		fmt.Fprintf(&b, "\n")
	}
	b.WriteString(sn.base.StringTlv())
	return b.String()
}

func (sn *SnPdu) DecodeFromBytes(data []byte) error {
	err := sn.base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	//
	// SourceId
	copy(sn.sourceId[0:NEIGHBOUR_ID_LENGTH], data[10:10+NEIGHBOUR_ID_LENGTH])
	if sn.base.pduType == PDU_TYPE_LEVEL1_CSNP ||
		sn.base.pduType == PDU_TYPE_LEVEL2_CSNP {
		//
		// StartLspId
		copy(sn.startLspId[0:LSP_ID_LENGTH],
			data[10+NEIGHBOUR_ID_LENGTH:10+NEIGHBOUR_ID_LENGTH+LSP_ID_LENGTH])
		//
		// EndLspId
		copy(sn.endLspId[0:LSP_ID_LENGTH],
			data[10+NEIGHBOUR_ID_LENGTH+LSP_ID_LENGTH:10+NEIGHBOUR_ID_LENGTH+LSP_ID_LENGTH*2])
	}
	return nil
}

func (sn *SnPdu) Serialize() ([]byte, error) {
	data, err := sn.base.Serialize()
	if err != nil {
		return data, err
	}
	//
	// SourceId
	copy(data[10:10+NEIGHBOUR_ID_LENGTH], sn.sourceId[0:NEIGHBOUR_ID_LENGTH])
	if sn.base.pduType == PDU_TYPE_LEVEL1_CSNP ||
		sn.base.pduType == PDU_TYPE_LEVEL2_CSNP {
		//
		// StartLspId
		copy(data[10+NEIGHBOUR_ID_LENGTH:10+NEIGHBOUR_ID_LENGTH+LSP_ID_LENGTH],
			sn.startLspId[0:LSP_ID_LENGTH])
		//
		// EndLspId
		copy(data[10+NEIGHBOUR_ID_LENGTH+LSP_ID_LENGTH:10+NEIGHBOUR_ID_LENGTH+LSP_ID_LENGTH*2],
			sn.endLspId[0:LSP_ID_LENGTH])
	}
	return data, nil
}

func (sn *SnPdu) BaseValid() bool {
	return sn.base.valid()
}

func (sn *SnPdu) SourceId() [NEIGHBOUR_ID_LENGTH]byte {
	return sn.sourceId
}

func (sn *SnPdu) SetSourceId(sourceId [NEIGHBOUR_ID_LENGTH]byte) error {
	sn.sourceId = sourceId
	return nil
}

func (sn *SnPdu) SetStartLspId(startLspId [LSP_ID_LENGTH]byte) error {
	sn.startLspId = startLspId
	return nil
}

func (sn *SnPdu) SetEndLspId(endLspId [LSP_ID_LENGTH]byte) error {
	sn.endLspId = endLspId
	return nil
}

func (sn *SnPdu) AddLspEntriesTlv(tlv *lspEntriesTlv) error {
	return sn.base.AddTlv(tlv)
}

func (sn *SnPdu) LspEntriesTlvs() ([]*lspEntriesTlv, error) {
	tlvs := make([]*lspEntriesTlv, 0)
	tlvstmp, err := sn.base.Tlvs(TLV_CODE_LSP_ENTRIES)
	if err != nil {
		return nil, err
	}
	for _, tlvtmp := range tlvstmp {
		if tlv, ok := tlvtmp.(*lspEntriesTlv); ok {
			tlvs = append(tlvs, tlv)
		}
	}
	return tlvs, nil
}

func (sn *SnPdu) ClearLspEntriesTlvs() error {
	return sn.base.ClearTlvs(TLV_CODE_LSP_ENTRIES)
}

func (sn *SnPdu) SetAuthInfoTlv(tlv *authInfoTlv) error {
	return sn.base.SetTlv(tlv)
}

func (sn *SnPdu) AuthInfoTlv() (*authInfoTlv, error) {
	tlvtmp, err := sn.base.Tlv(TLV_CODE_AUTH_INFO)
	if tlv, ok := tlvtmp.(*authInfoTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (sn *SnPdu) ClearAuthInfoTlvs() error {
	return sn.base.ClearTlvs(TLV_CODE_AUTH_INFO)
}
