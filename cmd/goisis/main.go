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
