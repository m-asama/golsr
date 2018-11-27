package packet

import (
	"bytes"
	"errors"
	"fmt"
)

type snPdu struct {
	base pduBase

	sourceId   []byte
	startLspId []byte // CSN
	endLspId   []byte // CSN
}

func NewSnPdu(pduType PduType) (*snPdu, error) {
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
	sn := snPdu{
		base: pduBase{
			lengthIndicator: lengthIndicator,
			pduType:         pduType,
		},
	}
	sn.base.init()
	sn.sourceId = make([]byte, 0)
	sn.startLspId = make([]byte, 0)
	sn.endLspId = make([]byte, 0)
	return &sn, nil
}

func (sn *snPdu) PduType() PduType {
	return sn.base.pduType
}

func (sn *snPdu) String() string {
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

func (sn *snPdu) DecodeFromBytes(data []byte) error {
	err := sn.base.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	//
	// SourceId
	sourceId := make([]byte, sn.base.idLength+1)
	copy(sourceId, data[10:11+sn.base.idLength])
	sn.sourceId = sourceId
	if sn.base.pduType == PDU_TYPE_LEVEL1_CSNP ||
		sn.base.pduType == PDU_TYPE_LEVEL2_CSNP {
		//
		// StartLspId
		startLspId := make([]byte, sn.base.idLength+2)
		copy(startLspId, data[11+sn.base.idLength:13+sn.base.idLength*2])
		sn.startLspId = startLspId
		//
		// EndLspId
		endLspId := make([]byte, sn.base.idLength+2)
		copy(endLspId, data[13+sn.base.idLength*2:15+sn.base.idLength*3])
		sn.endLspId = endLspId
	}
	return nil
}

func (sn *snPdu) Serialize() ([]byte, error) {
	data, err := sn.base.Serialize()
	if err != nil {
		return data, err
	}
	//
	// SourceId
	copy(data[10:11+sn.base.idLength], sn.sourceId)
	if sn.base.pduType == PDU_TYPE_LEVEL1_CSNP ||
		sn.base.pduType == PDU_TYPE_LEVEL2_CSNP {
		//
		// StartLspId
		copy(data[11+sn.base.idLength:13+sn.base.idLength*2], sn.startLspId)
		//
		// EndLspId
		copy(data[13+sn.base.idLength*2:15+sn.base.idLength*3], sn.endLspId)
	}
	return data, nil
}

func (sn *snPdu) AddLspEntriesTlv(tlv *lspEntriesTlv) error {
	return sn.base.AddTlv(tlv)
}

func (sn *snPdu) LspEntriesTlvs() ([]*lspEntriesTlv, error) {
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

func (sn *snPdu) ClearLspEntriesTlvs() error {
	return sn.base.ClearTlvs(TLV_CODE_LSP_ENTRIES)
}

func (sn *snPdu) SetAuthInfoTlv(tlv *authInfoTlv) error {
	return sn.base.SetTlv(tlv)
}

func (sn *snPdu) AuthInfoTlv() (*authInfoTlv, error) {
	tlvtmp, err := sn.base.Tlv(TLV_CODE_AUTH_INFO)
	if tlv, ok := tlvtmp.(*authInfoTlv); ok {
		return tlv, err
	}
	return nil, err
}

func (sn *snPdu) ClearAuthInfoTlvs() error {
	return sn.base.ClearTlvs(TLV_CODE_AUTH_INFO)
}
