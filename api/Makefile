
.PHONY: all

all: goisis.pb.go

goisis.pb.go: goisis.proto
	protoc --go_out=plugins=grpc:. goisis.proto

