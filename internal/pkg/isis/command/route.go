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

func printRoute(route *api.Route) {
	//fmt.Printf("Level             : %s\n", route.Level)
	switch route.Level {
	case "level-1":
		fmt.Printf("L1 ")
	case "level-2":
		fmt.Printf("L2 ")
	default:
		fmt.Printf("L? ")
	}
	fmt.Printf("%-30s ", route.Prefix)
	fmt.Printf("%5d ", route.Metric)
	first := true
	for _, nh := range route.NextHops {
		if !first {
			fmt.Printf("                                        ")
		}
		fmt.Printf("%-8s %-30s\n", nh.OutgoingInterface, nh.NextHop)
		if first {
			first = false
		}
	}
}

func NewRouteCmd() *cobra.Command {
	routeCmd := &cobra.Command{
		Use: "route",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 2 {
				return
			}
			stream, _ := client.DbRiMonitor(ctx, &api.DbRiMonitorRequest{
				Level:         args[0],
				AddressFamily: args[1],
			})
			fmt.Printf("LV %-30s %5s %-8s %-30s\n", "PREFIX", "DIST", "I/F", "NEXTHOP")
			for {
				r, err := stream.Recv()
				if err == io.EOF {
					break
				} else if err != nil {
					return
				}
				for _, route := range r.Routes {
					printRoute(route)
				}
			}
		},
	}

	return routeCmd
}
