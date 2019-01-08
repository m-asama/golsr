package server

func plen2snmask4(plen uint8) uint32 {
	return uint32(((uint64(1) << plen) - 1) << (32 - plen))
}
