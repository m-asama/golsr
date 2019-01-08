package server

import (
	"fmt"
	"net"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	api "github.com/m-asama/golsr/api"
	"github.com/m-asama/golsr/pkg/isis/packet"
)

type ApiServer struct {
	isisServer *IsisServer
	grpcServer *grpc.Server
	hosts      string
}

func NewApiServer(i *IsisServer, g *grpc.Server, hosts string) *ApiServer {
	log.Debugf("enter")
	defer log.Debugf("exit")
	grpc.EnableTracing = false
	s := &ApiServer{
		isisServer: i,
		grpcServer: g,
		hosts:      hosts,
	}
	api.RegisterGoisisApiServer(g, s)
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
	if s.isisServer.enable() {
		response.Result = "already enabled"
	} else {
		s.isisServer.SetEnable()
		//s.isisServer.checkChanged()
		s.isisServer.updateCh <- &UpdateChMsg{
			msgType: UPDATE_CH_MSG_TYPE_ISIS_ENABLE,
		}
		response.Result = "enabled"
	}
	return response, nil
}

func (s *ApiServer) Disable(ctx context.Context, in *api.DisableRequest) (*api.DisableResponse, error) {
	log.Debugf("enter")
	defer log.Debugf("exit")
	response := &api.DisableResponse{}
	if s.isisServer.enable() {
		s.isisServer.SetDisable()
		//s.isisServer.checkChanged()
		s.isisServer.updateCh <- &UpdateChMsg{
			msgType: UPDATE_CH_MSG_TYPE_ISIS_DISABLE,
		}
		response.Result = "disabled"
	} else {
		response.Result = "already disabled"
	}
	return response, nil
}

func (s *ApiServer) InterfaceEnable(ctx context.Context, in *api.InterfaceEnableRequest) (*api.InterfaceEnableResponse, error) {
	log.Debugf("enter")
	defer log.Debugf("exit")
	response := &api.InterfaceEnableResponse{}
	found := false
	for _, iface := range s.isisServer.circuitDb {
		if iface.name == in.Interface {
			found = true
			if iface.enable() {
				response.Result = "already enabled"
			} else {
				iface.SetEnable()
				//s.isisServer.checkChanged()
				s.isisServer.updateCh <- &UpdateChMsg{
					msgType: UPDATE_CH_MSG_TYPE_CIRCUIT_UP,
					circuit: iface,
				}
				response.Result = "enabled"
			}
		}
	}
	if !found {
		response.Result = "interface not found"
	}
	return response, nil
}

func (s *ApiServer) InterfaceDisable(ctx context.Context, in *api.InterfaceDisableRequest) (*api.InterfaceDisableResponse, error) {
	log.Debugf("enter")
	defer log.Debugf("exit")
	response := &api.InterfaceDisableResponse{}
	found := false
	for _, iface := range s.isisServer.circuitDb {
		if iface.name == in.Interface {
			found = true
			if iface.enable() {
				iface.SetDisable()
				//s.isisServer.checkChanged()
				s.isisServer.updateCh <- &UpdateChMsg{
					msgType: UPDATE_CH_MSG_TYPE_CIRCUIT_DOWN,
					circuit: iface,
				}
				response.Result = "disabled"
			} else {
				response.Result = "already disabled"
			}
		}
	}
	if !found {
		response.Result = "interface not found"
	}
	return response, nil
}

func (s *ApiServer) AdjacencyGet(ctx context.Context, in *api.AdjacencyGetRequest) (*api.AdjacencyGetResponse, error) {
	log.Debugf("enter")
	defer log.Debugf("exit")
	return nil, nil
}

func (s *ApiServer) AdjacencyMonitor(in *api.AdjacencyMonitorRequest, stream api.GoisisApi_AdjacencyMonitorServer) error {
	log.Debugf("enter")
	defer log.Debugf("exit")
	for _, iface := range s.isisServer.circuitDb {
		if in.Interface != "all" && iface.name != in.Interface {
			continue
		}
		adjacencies := make([]*api.Adjacency, 0)
		for _, adj := range iface.adjacencyDb {
			adjacency := &api.Adjacency{
				Interface:                 iface.name,
				NeighborType:              adj.adjType.String(),
				NeighborSysid:             fmt.Sprintf("%x", adj.systemId),
				NeighborExtendedCircuitId: adj.extendedCircuitId,
				NeighborSnpa:              fmt.Sprintf("%x", adj.lanAddress),
				Usage:                     adj.adjUsage.String(),
				HoldTimer:                 uint32(adj.holdingTime),
				NeighborPriority:          uint32(adj.priority),
				Lastuptime:                0,
				State:                     adj.adjState.String(),
			}
			adjacencies = append(adjacencies, adjacency)
		}
		r := &api.AdjacencyMonitorResponse{
			Adjacency: adjacencies,
		}
		stream.Send(r)
	}
	return nil
}

func (s *ApiServer) DbLsGet(ctx context.Context, in *api.DbLsGetRequest) (*api.DbLsGetResponse, error) {
	log.Debugf("enter")
	defer log.Debugf("exit")
	return nil, nil
}

func fillLsp(apiLsp *api.Lsp, packetLsp *packet.LsPdu) {
	log.Debugf("enter")
	defer log.Debugf("exit")
	apiLsp.Level = "??"
	switch packetLsp.PduType() {
	case packet.PDU_TYPE_LEVEL1_LSP:
		apiLsp.Level = "L1"
	case packet.PDU_TYPE_LEVEL2_LSP:
		apiLsp.Level = "L2"
	}
	apiLsp.LspId = fmt.Sprintf("%x", packetLsp.LspId())
	apiLsp.Checksum = uint32(packetLsp.Checksum)
	apiLsp.RemainingLifetime = uint32(packetLsp.RemainingLifetime)
	apiLsp.Sequence = packetLsp.SequenceNumber
}

func (s *ApiServer) DbLsMonitor(in *api.DbLsMonitorRequest, stream api.GoisisApi_DbLsMonitorServer) error {
	log.Debugf("enter")
	defer log.Debugf("exit")
	if in.Level == "level-1" || in.Level == "all" {
		lsps := make([]*api.Lsp, 0)
		s.isisServer.lock.Lock()
		for _, lsptmp := range s.isisServer.lsDb[ISIS_LEVEL_1] {
			lsp := &api.Lsp{}
			fillLsp(lsp, lsptmp.pdu)
			lsps = append(lsps, lsp)
		}
		s.isisServer.lock.Unlock()
		log.Debugf("len(lsps) = %d", len(lsps))
		r := &api.DbLsMonitorResponse{
			Lsp: lsps,
		}
		stream.Send(r)
	}
	if in.Level == "level-2" || in.Level == "all" {
		lsps := make([]*api.Lsp, 0)
		s.isisServer.lock.Lock()
		for _, lsptmp := range s.isisServer.lsDb[ISIS_LEVEL_2] {
			lsp := &api.Lsp{}
			fillLsp(lsp, lsptmp.pdu)
			lsps = append(lsps, lsp)
		}
		s.isisServer.lock.Unlock()
		log.Debugf("len(lsps) = %d", len(lsps))
		r := &api.DbLsMonitorResponse{
			Lsp: lsps,
		}
		stream.Send(r)
	}
	return nil
}
