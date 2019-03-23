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

package server

import (
	"net"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	api "github.com/m-asama/golsr/api/ospf"
	_ "github.com/m-asama/golsr/internal/pkg/util"
	_ "github.com/m-asama/golsr/pkg/ospf/packet"
)

type ApiServer struct {
	ospfServer *OspfServer
	grpcServer *grpc.Server
	hosts      string
}

func NewApiServer(i *OspfServer, g *grpc.Server, hosts string) *ApiServer {
	log.Debugf("enter")
	defer log.Debugf("exit")
	grpc.EnableTracing = false
	s := &ApiServer{
		ospfServer: i,
		grpcServer: g,
		hosts:      hosts,
	}
	api.RegisterGoospfApiServer(g, s)
	return s
}

func (s *ApiServer) Serve(wg *sync.WaitGroup) {
	log.Debugf("enter")
	defer log.Debugf("exit")
	defer wg.Done()

	serve := func(host string) {
		log.Debugf("enter")
		defer log.Debugf("exit")
		defer wg.Done()
		lis, err := net.Listen("tcp", host)
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "grpc",
				"Key":   host,
				"Error": err,
			}).Warn("listen failed")
			return
		}
		err = s.grpcServer.Serve(lis)
		log.WithFields(log.Fields{
			"Topic": "grpc",
			"Key":   host,
			"Error": err,
		}).Warn("accept failed")
	}

	l := strings.Split(s.hosts, ",")
	for _, host := range l {
		wg.Add(1)
		go serve(host)
	}
}

func (s *ApiServer) Exit() {
	log.Debugf("enter")
	defer log.Debugf("exit")
	s.grpcServer.Stop()
}

func (s *ApiServer) Enable(ctx context.Context, in *api.EnableRequest) (*api.EnableResponse, error) {
	log.Debugf("enter")
	defer log.Debugf("exit")
	response := &api.EnableResponse{}
	if s.ospfServer.enable() {
		response.Result = "already enabled"
	} else {
		s.ospfServer.SetEnable()
		response.Result = "enabled"
	}
	return response, nil
}

func (s *ApiServer) Disable(ctx context.Context, in *api.DisableRequest) (*api.DisableResponse, error) {
	log.Debugf("enter")
	defer log.Debugf("exit")
	response := &api.DisableResponse{}
	if s.ospfServer.enable() {
		s.ospfServer.SetDisable()
		response.Result = "disabled"
	} else {
		response.Result = "already disabled"
	}
	return response, nil
}
