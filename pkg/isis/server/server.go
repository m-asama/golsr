package server

import (
	_ "fmt"
	"net"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	api "github.com/m-asama/golsr/api"
	"github.com/m-asama/golsr/internal/pkg/isis/config"
)

type Interface struct {
}

type IsisServer struct {
	isisConfig config.IsisConfig

	interfaceMap map[string]*Interface
}

type Server struct {
	isisServer *IsisServer
	grpcServer *grpc.Server
	hosts      string
}

func NewIsisServer() *IsisServer {
	s := &IsisServer{
		interfaceMap: make(map[string]*Interface),
	}
	return s
}

func NewGrpcServer(i *IsisServer, hosts string) *Server {
	size := 256 << 20
	return NewServer(i, grpc.NewServer(grpc.MaxRecvMsgSize(size), grpc.MaxSendMsgSize(size)), hosts)
}

func NewServer(i *IsisServer, g *grpc.Server, hosts string) *Server {
	grpc.EnableTracing = false
	s := &Server{
		isisServer: i,
		grpcServer: g,
		hosts:      hosts,
	}
	api.RegisterGoisisApiServer(g, s)
	return s
}

func (s *IsisServer) Serve() {
	ch := make(chan int)
	for {
		select {
		case <-ch:
		}
	}
}

func (s *Server) Serve() error {
	var wg sync.WaitGroup
	l := strings.Split(s.hosts, ",")
	wg.Add(len(l))

	serve := func(host string) {
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

	for _, host := range l {
		go serve(host)
	}
	wg.Wait()
	return nil
}
