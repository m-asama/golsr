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
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	api "github.com/m-asama/golsr/api/ospf"
)

var globalOpts struct {
	Host         string
	Port         int
	Debug        bool
	Quiet        bool
	Json         bool
	GenCmpl      bool
	BashCmplFile string
}

var client api.GoospfApiClient
var ctx context.Context

func printError(err error) {
	if globalOpts.Json {
		j, _ := json.Marshal(struct {
			Error string `json:"error"`
		}{Error: err.Error()})
		fmt.Println(string(j))
	} else {
		fmt.Println(err)
	}
}

func exitWithError(err error) {
	printError(err)
	os.Exit(1)
}

func newClient(ctx context.Context) (api.GoospfApiClient, error) {
	grpcOpts := []grpc.DialOption{grpc.WithTimeout(time.Second), grpc.WithBlock()}
	grpcOpts = append(grpcOpts, grpc.WithInsecure())

	target := net.JoinHostPort(globalOpts.Host, strconv.Itoa(globalOpts.Port))
	if target == "" {
		target = ":50052"
	}

	conn, err := grpc.DialContext(ctx, target, grpcOpts...)
	if err != nil {
		return nil, err
	}
	return api.NewGoospfApiClient(conn), nil
}

func NewRootCmd() *cobra.Command {
	cobra.EnablePrefixMatching = true
	rootCmd := &cobra.Command{
		Use: "goospf",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if !globalOpts.GenCmpl {
				var err error
				ctx = context.Background()
				client, err = newClient(ctx)
				if err != nil {
					exitWithError(err)
				}
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			if globalOpts.GenCmpl {
				cmd.GenBashCompletionFile(globalOpts.BashCmplFile)
			} else {
				cmd.HelpFunc()(cmd, args)
			}
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
		},
	}

	rootCmd.PersistentFlags().StringVarP(&globalOpts.Host, "host", "u", "127.0.0.1", "host")
	rootCmd.PersistentFlags().IntVarP(&globalOpts.Port, "port", "p", 50052, "port")
	rootCmd.PersistentFlags().BoolVarP(&globalOpts.Json, "json", "j", false, "use json format to output format")
	rootCmd.PersistentFlags().BoolVarP(&globalOpts.Debug, "debug", "d", false, "use debug")
	rootCmd.PersistentFlags().BoolVarP(&globalOpts.Quiet, "quiet", "q", false, "use quiet")
	rootCmd.PersistentFlags().BoolVarP(&globalOpts.GenCmpl, "gen-cmpl", "c", false, "generate completion file")
	rootCmd.PersistentFlags().StringVarP(&globalOpts.BashCmplFile, "bash-cmpl-file", "", "goospf-completion.bash",
		"bash cmpl filename")

	enableCmd := &cobra.Command{
		Use: "enable",
		Run: func(cmd *cobra.Command, args []string) {
			response, _ := client.Enable(ctx, &api.EnableRequest{})
			fmt.Println(response.Result)
		},
	}
	rootCmd.AddCommand(enableCmd)

	disableCmd := &cobra.Command{
		Use: "disable",
		Run: func(cmd *cobra.Command, args []string) {
			response, _ := client.Disable(ctx, &api.DisableRequest{})
			fmt.Println(response.Result)
		},
	}
	rootCmd.AddCommand(disableCmd)

	/*
		interfaceCmd := NewInterfaceCmd()
		rootCmd.AddCommand(interfaceCmd)

		databaseCmd := NewDatabaseCmd()
		rootCmd.AddCommand(databaseCmd)

		routeCmd := NewRouteCmd()
		rootCmd.AddCommand(routeCmd)
	*/

	return rootCmd
}
