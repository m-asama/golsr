package kernel

import (
	"bytes"
	"fmt"
	"testing"
)

func TestKernel(t *testing.T) {
	var b bytes.Buffer
	info := NewKernelInfo()
	if info == nil {
		t.Fatalf("NewKernelInfo")
	}
	for _, iface := range info.Interfaces {
		fmt.Fprintf(&b, "InterfaceName = %s\n", iface.Name)
		for _, addr4 := range iface.Ipv4Addresses {
			fmt.Fprintf(&b, "\t%08x/%d\n", addr4.Address, addr4.PrefixLength)
		}
		for _, addr6 := range iface.Ipv6Addresses {
			fmt.Fprintf(&b, "\t%08x:%08x:%08x:%08x/%d %t\n",
				addr6.Address[0], addr6.Address[1], addr6.Address[2], addr6.Address[3],
				addr6.PrefixLength, addr6.ScopeLink)
		}
	}
	t.Fatalf("\n%s", b.String())
}
