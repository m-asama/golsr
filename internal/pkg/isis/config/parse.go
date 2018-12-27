package config

import (
	"bytes"
	"strconv"

	_ "github.com/sirupsen/logrus"

	"github.com/m-asama/golsr/pkg/isis/packet"
)

func ParseSystemId(systemIdStr string) []byte {
	var tmp int64
	systemId := make([]byte, packet.SYSTEM_ID_LENGTH)
	tmp, _ = strconv.ParseInt(systemIdStr[0:2], 16, 16)
	systemId[0] = byte(tmp)
	tmp, _ = strconv.ParseInt(systemIdStr[2:4], 16, 16)
	systemId[1] = byte(tmp)
	tmp, _ = strconv.ParseInt(systemIdStr[5:7], 16, 16)
	systemId[2] = byte(tmp)
	tmp, _ = strconv.ParseInt(systemIdStr[7:9], 16, 16)
	systemId[3] = byte(tmp)
	tmp, _ = strconv.ParseInt(systemIdStr[10:12], 16, 16)
	systemId[4] = byte(tmp)
	tmp, _ = strconv.ParseInt(systemIdStr[12:14], 16, 16)
	systemId[5] = byte(tmp)
	return systemId
}

func ParseAreaAddresses(areaAddressesStrs []*string) [][]byte {
	areaAddresses := make([][]byte, len(areaAddressesStrs))
	for i, areaAddressStr := range areaAddressesStrs {
		var tmp int64
		areaAddress := make([]byte, 0)
		tmp, _ = strconv.ParseInt((*areaAddressStr)[0:2], 16, 16)
		areaAddress = append(areaAddress, byte(tmp))
		if len(*areaAddressStr) > 3 {
			tmp, _ = strconv.ParseInt((*areaAddressStr)[3:5], 16, 16)
			areaAddress = append(areaAddress, byte(tmp))
			tmp, _ = strconv.ParseInt((*areaAddressStr)[5:7], 16, 16)
			areaAddress = append(areaAddress, byte(tmp))
		}
		if len(*areaAddressStr) > 8 {
			tmp, _ = strconv.ParseInt((*areaAddressStr)[8:10], 16, 16)
			areaAddress = append(areaAddress, byte(tmp))
			tmp, _ = strconv.ParseInt((*areaAddressStr)[10:12], 16, 16)
			areaAddress = append(areaAddress, byte(tmp))
		}
		if len(*areaAddressStr) > 13 {
			tmp, _ = strconv.ParseInt((*areaAddressStr)[13:15], 16, 16)
			areaAddress = append(areaAddress, byte(tmp))
			tmp, _ = strconv.ParseInt((*areaAddressStr)[15:17], 16, 16)
			areaAddress = append(areaAddress, byte(tmp))
		}
		areaAddresses[i] = areaAddress
	}
	// XXX:
	for i := 0; i < len(areaAddresses); i++ {
		for j := 0; j < len(areaAddresses); j++ {
			if i == j {
				break
			}
			if bytes.Compare(areaAddresses[i], areaAddresses[j]) < 0 {
				tmp := areaAddresses[i]
				areaAddresses[i] = areaAddresses[j]
				areaAddresses[j] = tmp
			}
		}
	}
	return areaAddresses
}
