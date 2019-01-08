package kernel

import (
	"encoding/binary"
	"net"

	log "github.com/sirupsen/logrus"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type IfType int

const (
	_                    IfType = iota
	IF_TYPE_LOOPBACK            = 1
	IF_TYPE_BROADCAST           = 2
	IF_TYPE_POINTTOPOINT        = 3
)

type Ipv4Address struct {
	Address      uint32
	PrefixLength int
	ScopeHost    bool
}

type Ipv6Address struct {
	Address      [4]uint32
	PrefixLength int
	ScopeLink    bool
	ScopeHost    bool
}

type Interface struct {
	IfIndex       int
	Name          string
	IfType        IfType
	HardwareAddr  []byte
	Mtu           int
	Up            bool
	Ipv4Addresses []*Ipv4Address
	Ipv6Addresses []*Ipv6Address
}

type KernelStatus struct {
	Interfaces []*Interface
}

func NewIpv4Address(addr *netlink.Addr) *Ipv4Address {
	if len(addr.IP) != 4 {
		return nil
	}
	ipv4Address := &Ipv4Address{}
	ipv4Address.Address = binary.BigEndian.Uint32(addr.IP[0:4])
	ipv4Address.PrefixLength, _ = addr.Mask.Size()
	ipv4Address.ScopeHost = (addr.Scope == unix.RT_SCOPE_HOST)
	return ipv4Address
}

func NewIpv6Address(addr *netlink.Addr) *Ipv6Address {
	if len(addr.IP) != 16 {
		return nil
	}
	ipv6Address := &Ipv6Address{}
	ipv6Address.Address[0] = binary.BigEndian.Uint32(addr.IP[0:4])
	ipv6Address.Address[1] = binary.BigEndian.Uint32(addr.IP[4:8])
	ipv6Address.Address[2] = binary.BigEndian.Uint32(addr.IP[8:12])
	ipv6Address.Address[3] = binary.BigEndian.Uint32(addr.IP[12:16])
	ipv6Address.PrefixLength, _ = addr.Mask.Size()
	ipv6Address.ScopeLink = (addr.Scope == unix.RT_SCOPE_LINK)
	ipv6Address.ScopeHost = (addr.Scope == unix.RT_SCOPE_HOST)
	return ipv6Address
}

func ifType(flags net.Flags) IfType {
	var ifType IfType
	if (flags & net.FlagLoopback) != 0 {
		ifType = IF_TYPE_LOOPBACK
	}
	if (flags & net.FlagBroadcast) != 0 {
		ifType = IF_TYPE_BROADCAST
	}
	if (flags & net.FlagPointToPoint) != 0 {
		ifType = IF_TYPE_POINTTOPOINT
	}
	return ifType
}

func NewInterface(attrs *netlink.LinkAttrs) *Interface {
	if attrs == nil {
		return nil
	}
	ifType := ifType(attrs.Flags)
	if ifType == 0 {
		return nil
	}
	iface := &Interface{}
	iface.IfIndex = attrs.Index
	iface.Name = attrs.Name
	iface.IfType = ifType
	iface.HardwareAddr = attrs.HardwareAddr
	iface.Mtu = attrs.MTU
	iface.Up = ((attrs.Flags & net.FlagUp) != 0)
	iface.Ipv4Addresses = make([]*Ipv4Address, 0)
	iface.Ipv6Addresses = make([]*Ipv6Address, 0)
	return iface
}

func NewKernelStatus() *KernelStatus {
	status := &KernelStatus{}
	status.Interfaces = make([]*Interface, 0)

	links, err := netlink.LinkList()
	if err != nil {
		return nil
	}
	for _, link := range links {
		iface := NewInterface(link.Attrs())
		if iface == nil {
			continue
		}
		addr4s, err := netlink.AddrList(link, unix.AF_INET)
		if err != nil {
			return nil
		}
		for _, addr4 := range addr4s {
			ipv4Address := NewIpv4Address(&addr4)
			if ipv4Address != nil {
				iface.Ipv4Addresses = append(iface.Ipv4Addresses, ipv4Address)
			}
		}
		addr6s, err := netlink.AddrList(link, unix.AF_INET6)
		if err != nil {
			return nil
		}
		for _, addr6 := range addr6s {
			ipv6Address := NewIpv6Address(&addr6)
			if ipv6Address != nil {
				iface.Ipv6Addresses = append(iface.Ipv6Addresses, ipv6Address)
			}
		}
		status.Interfaces = append(status.Interfaces, iface)
	}

	return status
}

func Serve(status chan<- *KernelStatus) {
	log.Debugf("enter")
	defer log.Debugf("exit")
	addrCh := make(chan netlink.AddrUpdate)
	addrDone := make(chan struct{})
	netlink.AddrSubscribe(addrCh, addrDone)
	linkCh := make(chan netlink.LinkUpdate)
	linkDone := make(chan struct{})
	netlink.LinkSubscribe(linkCh, linkDone)
	status <- NewKernelStatus()
	for {
		select {
		case <-addrCh:
		case <-linkCh:
		}
		status <- NewKernelStatus()
	}
}

func IfaceExists(name string) bool {
	links, err := netlink.LinkList()
	if err != nil {
		return false
	}
	for _, link := range links {
		attrs := link.Attrs()
		if attrs.Name == name {
			return true
		}
	}
	return false
}

func IfaceType(name string) IfType {
	links, err := netlink.LinkList()
	if err != nil {
		return IfType(0)
	}
	for _, link := range links {
		attrs := link.Attrs()
		if attrs.Name == name {
			return ifType(attrs.Flags)
		}
	}
	return IfType(0)
}
