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

func printAdjacency(adj *api.Adjacency) {
	fmt.Printf("Interface                 : %s\n", adj.Interface)
	fmt.Printf("NeighborType              : %s\n", adj.NeighborType)
	fmt.Printf("NeighborSysid             : %s\n", adj.NeighborSysid)
	fmt.Printf("NeighborExtendedCircuitId : %d\n", adj.NeighborExtendedCircuitId)
	fmt.Printf("NeighborSnpa              : %s\n", adj.NeighborSnpa)
	fmt.Printf("Usage                     : %s\n", adj.Usage)
	fmt.Printf("HoldTimer                 : %d\n", adj.HoldTimer)
	fmt.Printf("NeighborPriority          : %d\n", adj.NeighborPriority)
	fmt.Printf("Lastuptime                : %s\n", adj.Lastuptime)
	fmt.Printf("State                     : %s\n", adj.State)
	fmt.Printf("\n")
}

func NewIfEnableCmd() *cobra.Command {
	ifEnableCmd := &cobra.Command{
		Use: "enable",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				return
			}
			request := &api.InterfaceEnableRequest{Interface: args[0]}
			response, _ := client.InterfaceEnable(ctx, request)
			fmt.Println(response.Result)
		},
	}
	return ifEnableCmd
}

func NewIfDisableCmd() *cobra.Command {
	ifDisableCmd := &cobra.Command{
		Use: "disable",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				return
			}
			request := &api.InterfaceDisableRequest{Interface: args[0]}
			response, _ := client.InterfaceDisable(ctx, request)
			fmt.Println(response.Result)
		},
	}
	return ifDisableCmd
}

func NewIfAdjacencyCmd() *cobra.Command {
	ifAdjacencyCmd := &cobra.Command{
		Use: "adjacency",
		Run: func(cmd *cobra.Command, args []string) {
			ifname := "all"
			if len(args) > 0 {
				ifname = args[0]
			}
			stream, _ := client.AdjacencyMonitor(ctx, &api.AdjacencyMonitorRequest{
				Interface: ifname,
			})
			for {
				r, err := stream.Recv()
				if err == io.EOF {
					break
				} else if err != nil {
					return
				}
				for _, adj := range r.Adjacencies {
					printAdjacency(adj)
				}
			}
		},
	}
	return ifAdjacencyCmd
}

func NewInterfaceCmd() *cobra.Command {
	interfaceCmd := &cobra.Command{
		Use: "interface",
		Run: func(cmd *cobra.Command, args []string) {
		},
	}

	ifEnableCmd := NewIfEnableCmd()
	interfaceCmd.AddCommand(ifEnableCmd)

	ifDisableCmd := NewIfDisableCmd()
	interfaceCmd.AddCommand(ifDisableCmd)

	ifAdjacencyCmd := NewIfAdjacencyCmd()
	interfaceCmd.AddCommand(ifAdjacencyCmd)

	return interfaceCmd
}
