//
// Copyright (C) 2019-2019 Masakazu Asama.
// Copyright (C) 2019-2019 Ginzado Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kernel

import (
	"bytes"
	"fmt"
	"testing"
)

func TestKernel(t *testing.T) {
	var b bytes.Buffer
	info := NewKernelStatus()
	if info == nil {
		t.Fatalf("NewKernelStatus")
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
	//t.Fatalf("\n%s", b.String())
}
