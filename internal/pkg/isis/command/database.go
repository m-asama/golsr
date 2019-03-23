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

package command

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	api "github.com/m-asama/golsr/api/isis"
)

func printLsp(lsp *api.Lsp) {
	fmt.Printf("Level             : %s\n", lsp.Level)
	fmt.Printf("LspId             : %s\n", lsp.LspId)
	fmt.Printf("Checksum          : 0x%04x\n", lsp.Checksum)
	fmt.Printf("RemainingLifetime : %d\n", lsp.RemainingLifetime)
	fmt.Printf("Sequence          : 0x%04x(%d)\n", lsp.Sequence, lsp.Sequence)
	fmt.Printf("Ipv4Addresses     : %s\n", lsp.Ipv4Addresses)
	fmt.Printf("Ipv6Addresses     : %s\n", lsp.Ipv6Addresses)
	fmt.Printf("Ipv4TeRouterid    : %s\n", lsp.Ipv4TeRouterid)
	fmt.Printf("Ipv6TeRouterid    : %s\n", lsp.Ipv6TeRouterid)
	fmt.Printf("ProtocolSupported : %s\n", lsp.ProtocolSupporteds)
	fmt.Printf("DynamicHostname   : %s\n", lsp.DynamicHostname)
	fmt.Printf("\n")
}

func NewDbLinkstateCmd() *cobra.Command {
	dbLinkstateCmd := &cobra.Command{
		Use: "linkstate",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				return
			}
			stream, _ := client.DbLsMonitor(ctx, &api.DbLsMonitorRequest{
				Level: args[0],
			})
			for {
				r, err := stream.Recv()
				if err == io.EOF {
					break
				} else if err != nil {
					return
				}
				for _, lsp := range r.Lsps {
					printLsp(lsp)
				}
			}
		},
	}
	return dbLinkstateCmd
}

func NewDatabaseCmd() *cobra.Command {
	databaseCmd := &cobra.Command{
		Use: "database",
		Run: func(cmd *cobra.Command, args []string) {
		},
	}

	dbLinkstateCmd := NewDbLinkstateCmd()
	databaseCmd.AddCommand(dbLinkstateCmd)

	return databaseCmd
}
