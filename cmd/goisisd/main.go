package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"

	"github.com/jessevdk/go-flags"
	"github.com/kr/pretty"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	api "github.com/m-asama/golsr/api"
	"github.com/m-asama/golsr/internal/pkg/isis/config"
	"github.com/m-asama/golsr/pkg/isis/server"
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
		GrpcHosts     string `long:"api-hosts" description:"specify the hosts that goisisd listens on" default:":50052"`
		Dry           bool   `short:"d" long:"dry-run" description:"check configuration"`
		Version       bool   `long:"version" description:"show version number"`
	}
	_, err := flags.Parse(&opts)
	if err != nil {
		os.Exit(1)
	}

	if opts.Version {
		fmt.Println("goisisd version", version)
		os.Exit(0)
	}

	switch opts.LogLevel {
	case "debug":
		log.SetLevel(log.DebugLevel)
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

	var c *config.IsisConfig

	configCh := make(chan *config.IsisConfig)
	if opts.Dry {
		go config.ReadConfigfileServe(opts.ConfigFile, opts.ConfigType, configCh)
		c = <-configCh
		if opts.LogLevel == "debug" {
			pretty.Println(c)
		}
		os.Exit(0)
	}

	log.Info("goisisd started")
	isisServer := server.NewIsisServer()
	go isisServer.Serve()

	var grpcOpts []grpc.ServerOption

	apiServer := server.NewServer(isisServer, grpc.NewServer(grpcOpts...), opts.GrpcHosts)
	go func() {
		if err := apiServer.Serve(); err != nil {
			log.Fatalf("failed to listen grpc port: %s", err)
		}
	}()

	if opts.ConfigFile != "" {
		go config.ReadConfigfileServe(opts.ConfigFile, opts.ConfigType, configCh)
	}

	for {
		select {
		case <-sigCh:
			apiServer.StopIsis(context.Background(), &api.StopIsisRequest{})
		case newConfig := <-configCh:
			_ = newConfig
			log.Infof("newConfig")
		}
	}
}
