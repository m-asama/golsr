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
	"io/ioutil"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/jessevdk/go-flags"
	"github.com/kr/pretty"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	api "github.com/m-asama/golsr/api/ospf"
	"github.com/m-asama/golsr/internal/pkg/ospf/config"
	"github.com/m-asama/golsr/pkg/ospf/server"
)

var version = "master"

func main() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM)
	var opts struct {
		ConfigFile    string `short:"f" long:"config-file" description:"specifying a config file"`
		ConfigType    string `short:"t" long:"config-type" description:"specifying config type (toml, yaml, json)" default:"toml"`
		LogLevel      string `short:"l" long:"log-level" description:"specifying log level"`
		LogPlain      bool   `short:"p" long:"log-plain" description:"use plain format for logging (json by default)"`
		UseSyslog     string `short:"s" long:"syslog" description:"use syslogd"`
		Facility      string `long:"syslog-facility" description:"specify syslog facility"`
		DisableStdlog bool   `long:"disable-stdlog" description:"disable standard logging"`
		GrpcHosts     string `long:"api-hosts" description:"specify the hosts that goospfd listens on" default:":50052"`
		Dry           bool   `short:"d" long:"dry-run" description:"check configuration"`
		Version       bool   `long:"version" description:"show version number"`
	}
	_, err := flags.Parse(&opts)
	if err != nil {
		os.Exit(1)
	}

	if opts.Version {
		fmt.Println("goospfd version", version)
		os.Exit(0)
	}

	switch opts.LogLevel {
	case "debug":
		log.SetLevel(log.DebugLevel)
		log.SetReportCaller(true)
	case "info":
		log.SetLevel(log.InfoLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}

	if opts.DisableStdlog {
		log.SetOutput(ioutil.Discard)
	} else {
		log.SetOutput(os.Stdout)
	}

	if opts.LogPlain {
		if opts.DisableStdlog {
			log.SetFormatter(&log.TextFormatter{
				DisableColors: true,
			})
		}
	} else {
		log.SetFormatter(&log.JSONFormatter{})
	}

	if opts.Dry {
		configCh := make(chan *config.OspfConfig)
		go config.Serve(opts.ConfigFile, opts.ConfigType, configCh)
		c := <-configCh
		if opts.LogLevel == "debug" {
			pretty.Println(c)
		}
		os.Exit(0)
	}

	var wg sync.WaitGroup

	log.Info("goospfd started")

	ospfServer := server.NewOspfServer(opts.ConfigFile, opts.ConfigType)
	wg.Add(1)
	go ospfServer.Serve(&wg)

	var grpcOpts []grpc.ServerOption
	apiServer := server.NewApiServer(ospfServer, grpc.NewServer(grpcOpts...), opts.GrpcHosts)
	wg.Add(1)
	go apiServer.Serve(&wg)

	<-sigCh

	log.Info("goospfd stoping")
	apiServer.Disable(context.Background(), &api.DisableRequest{})
	apiServer.Exit()
	ospfServer.Exit()

	wg.Wait()
	log.Info("goospfd terminated")
}
