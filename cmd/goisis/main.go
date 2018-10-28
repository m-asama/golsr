package main

import (
	"fmt"
	"os"

	"github.com/m-asama/golsr/internal/pkg/isis/command"
	"google.golang.org/grpc"
)

var version = "master"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println("goisis version", version)
		os.Exit(0)
	}
	grpc.EnableTracing = false
	command.NewRootCmd().Execute()
}
