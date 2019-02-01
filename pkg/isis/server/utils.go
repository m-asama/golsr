package server

func plen2snmask4(plen uint8) uint32 {
	return uint32(((uint64(1) << plen) - 1) << (32 - plen))
}

func snmask42plen(snmask uint32) uint8 {
	var i uint8
	for i = 0; i <= 32; i++ {
		if snmask == plen2snmask4(i) {
			return i
		}
	}
	return 32
}
