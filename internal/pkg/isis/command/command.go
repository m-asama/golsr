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

	api "github.com/m-asama/golsr/api"
)

var globalOpts struct {
	Host    string
	Port    int
	Debug   bool
	Quiet   bool
	Json    bool
	GenCmpl bool
	//BashCmplFile string
}

var client api.GoisisApiClient
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

func newClient(ctx context.Context) (api.GoisisApiClient, error) {
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
	return api.NewGoisisApiClient(conn), nil
}

func NewRootCmd() *cobra.Command {
	cobra.EnablePrefixMatching = true
	rootCmd := &cobra.Command{
		Use: "goisis",
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
			//			if globalOpts.GenCmpl {
			//				cmd.GenBashCompletionFile(globalOpts.BashCmplFile)
			//			} else {
			cmd.HelpFunc()(cmd, args)
			//			}
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
	//rootCmd.PersistentFlags().StringVarP(&globalOpts.BashCmplFile, "bash-cmpl-file", "", "goisis-completion.bash", "bash cmpl filename")

	databaseCmd := NewDatabaseCmd()
	rootCmd.AddCommand(databaseCmd)
	return rootCmd
}
