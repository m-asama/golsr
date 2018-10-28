package server

import (
	"github.com/golang/protobuf/ptypes/empty"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"

	api "github.com/m-asama/golsr/api"
)

func (s *Server) StartIsis(ctx context.Context, in *api.StartIsisRequest) (*empty.Empty, error) {
	return nil, nil
}

func (s *Server) StopIsis(ctx context.Context, in *api.StopIsisRequest) (*empty.Empty, error) {
	return nil, nil
}

func (s *Server) GetDatabase(ctx context.Context, in *api.GetDatabaseRequest) (*api.GetDatabaseResponse, error) {
	return nil, nil
}

func (s *Server) MonitorDatabase(in *api.MonitorDatabaseRequest, stream api.GoisisApi_MonitorDatabaseServer) error {
	log.Info("MonitorDatabase")
	return nil
}
