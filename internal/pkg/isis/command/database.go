package command

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	api "github.com/m-asama/golsr/api"
)

func NewDatabaseCmd() *cobra.Command {
	databaseCmd := &cobra.Command{
		Use: "database",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("exec database")
			stream, _ := client.MonitorDatabase(ctx, &api.MonitorDatabaseRequest{})
			for {
				r, err := stream.Recv()
				if err == io.EOF {
					break
				} else if err != nil {
					return
				}
				fmt.Println(r)
			}
		},
	}
	return databaseCmd
}
