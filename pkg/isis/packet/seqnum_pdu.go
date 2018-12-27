package packet

import (
	"bytes"
	"errors"
	"fmt"
)

type SnPdu struct {
	base pduBase

	sourceId   []byte
	startLspId []byte // CSN
	endLspId   []byte // CSN
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
	sn.sourceId = make([]byte, 0)
	sn.startLspId = make([]byte, 0)
	sn.endLspId = make([]byte, 0)
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

func (sn *SnPdu) Serialize() ([]byte, error) {
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

func (sn *SnPdu) BaseValid() bool {
	return sn.base.valid()
}

func (sn *SnPdu) SourceId() []byte {
	sourceId := make([]byte, len(sn.sourceId))
	copy(sourceId, sn.sourceId)
	return sourceId
}

func (sn *SnPdu) SetSourceId(sourceId []byte) error {
	if len(sourceId) != SYSTEM_ID_LENGTH {
		return errors.New("IihPdu.SetSourceId: sourceId length invalid")
	}
	sidtmp := make([]byte, len(sourceId))
	copy(sidtmp, sourceId)
	sn.sourceId = sourceId
	return nil
}

func (sn *SnPdu) SetStartLspId(startLspId []byte) error {
	if len(startLspId) != LSP_ID_LENGTH {
		return errors.New("IihPdu.SetStartLspId: LSP ID length invalid")
	}
	lidtmp := make([]byte, len(startLspId))
	copy(lidtmp, startLspId)
	sn.startLspId = startLspId
	return nil
}

func (sn *SnPdu) SetEndLspId(endLspId []byte) error {
	if len(endLspId) != LSP_ID_LENGTH {
		return errors.New("IihPdu.SetEndLspId: LSP ID length invalid")
	}
	lidtmp := make([]byte, len(endLspId))
	copy(lidtmp, endLspId)
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
