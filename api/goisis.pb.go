// Code generated by protoc-gen-go. DO NOT EDIT.
// source: goisis.proto

package goisisapi

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	empty "github.com/golang/protobuf/ptypes/empty"
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type StartIsisRequest struct {
	Global               *Global  `protobuf:"bytes,1,opt,name=global,proto3" json:"global,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *StartIsisRequest) Reset()         { *m = StartIsisRequest{} }
func (m *StartIsisRequest) String() string { return proto.CompactTextString(m) }
func (*StartIsisRequest) ProtoMessage()    {}
func (*StartIsisRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_07ca5a18eb6d27f6, []int{0}
}

func (m *StartIsisRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_StartIsisRequest.Unmarshal(m, b)
}
func (m *StartIsisRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_StartIsisRequest.Marshal(b, m, deterministic)
}
func (m *StartIsisRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_StartIsisRequest.Merge(m, src)
}
func (m *StartIsisRequest) XXX_Size() int {
	return xxx_messageInfo_StartIsisRequest.Size(m)
}
func (m *StartIsisRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_StartIsisRequest.DiscardUnknown(m)
}

var xxx_messageInfo_StartIsisRequest proto.InternalMessageInfo

func (m *StartIsisRequest) GetGlobal() *Global {
	if m != nil {
		return m.Global
	}
	return nil
}

type StopIsisRequest struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *StopIsisRequest) Reset()         { *m = StopIsisRequest{} }
func (m *StopIsisRequest) String() string { return proto.CompactTextString(m) }
func (*StopIsisRequest) ProtoMessage()    {}
func (*StopIsisRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_07ca5a18eb6d27f6, []int{1}
}

func (m *StopIsisRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_StopIsisRequest.Unmarshal(m, b)
}
func (m *StopIsisRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_StopIsisRequest.Marshal(b, m, deterministic)
}
func (m *StopIsisRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_StopIsisRequest.Merge(m, src)
}
func (m *StopIsisRequest) XXX_Size() int {
	return xxx_messageInfo_StopIsisRequest.Size(m)
}
func (m *StopIsisRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_StopIsisRequest.DiscardUnknown(m)
}

var xxx_messageInfo_StopIsisRequest proto.InternalMessageInfo

type GetDatabaseRequest struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetDatabaseRequest) Reset()         { *m = GetDatabaseRequest{} }
func (m *GetDatabaseRequest) String() string { return proto.CompactTextString(m) }
func (*GetDatabaseRequest) ProtoMessage()    {}
func (*GetDatabaseRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_07ca5a18eb6d27f6, []int{2}
}

func (m *GetDatabaseRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetDatabaseRequest.Unmarshal(m, b)
}
func (m *GetDatabaseRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetDatabaseRequest.Marshal(b, m, deterministic)
}
func (m *GetDatabaseRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetDatabaseRequest.Merge(m, src)
}
func (m *GetDatabaseRequest) XXX_Size() int {
	return xxx_messageInfo_GetDatabaseRequest.Size(m)
}
func (m *GetDatabaseRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GetDatabaseRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GetDatabaseRequest proto.InternalMessageInfo

type GetDatabaseResponse struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetDatabaseResponse) Reset()         { *m = GetDatabaseResponse{} }
func (m *GetDatabaseResponse) String() string { return proto.CompactTextString(m) }
func (*GetDatabaseResponse) ProtoMessage()    {}
func (*GetDatabaseResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_07ca5a18eb6d27f6, []int{3}
}

func (m *GetDatabaseResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetDatabaseResponse.Unmarshal(m, b)
}
func (m *GetDatabaseResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetDatabaseResponse.Marshal(b, m, deterministic)
}
func (m *GetDatabaseResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetDatabaseResponse.Merge(m, src)
}
func (m *GetDatabaseResponse) XXX_Size() int {
	return xxx_messageInfo_GetDatabaseResponse.Size(m)
}
func (m *GetDatabaseResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_GetDatabaseResponse.DiscardUnknown(m)
}

var xxx_messageInfo_GetDatabaseResponse proto.InternalMessageInfo

type MonitorDatabaseRequest struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *MonitorDatabaseRequest) Reset()         { *m = MonitorDatabaseRequest{} }
func (m *MonitorDatabaseRequest) String() string { return proto.CompactTextString(m) }
func (*MonitorDatabaseRequest) ProtoMessage()    {}
func (*MonitorDatabaseRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_07ca5a18eb6d27f6, []int{4}
}

func (m *MonitorDatabaseRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MonitorDatabaseRequest.Unmarshal(m, b)
}
func (m *MonitorDatabaseRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MonitorDatabaseRequest.Marshal(b, m, deterministic)
}
func (m *MonitorDatabaseRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MonitorDatabaseRequest.Merge(m, src)
}
func (m *MonitorDatabaseRequest) XXX_Size() int {
	return xxx_messageInfo_MonitorDatabaseRequest.Size(m)
}
func (m *MonitorDatabaseRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_MonitorDatabaseRequest.DiscardUnknown(m)
}

var xxx_messageInfo_MonitorDatabaseRequest proto.InternalMessageInfo

type MonitorDatabaseResponse struct {
	LevelDb              *LevelDb `protobuf:"bytes,1,opt,name=level_db,json=levelDb,proto3" json:"level_db,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *MonitorDatabaseResponse) Reset()         { *m = MonitorDatabaseResponse{} }
func (m *MonitorDatabaseResponse) String() string { return proto.CompactTextString(m) }
func (*MonitorDatabaseResponse) ProtoMessage()    {}
func (*MonitorDatabaseResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_07ca5a18eb6d27f6, []int{5}
}

func (m *MonitorDatabaseResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MonitorDatabaseResponse.Unmarshal(m, b)
}
func (m *MonitorDatabaseResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MonitorDatabaseResponse.Marshal(b, m, deterministic)
}
func (m *MonitorDatabaseResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MonitorDatabaseResponse.Merge(m, src)
}
func (m *MonitorDatabaseResponse) XXX_Size() int {
	return xxx_messageInfo_MonitorDatabaseResponse.Size(m)
}
func (m *MonitorDatabaseResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_MonitorDatabaseResponse.DiscardUnknown(m)
}

var xxx_messageInfo_MonitorDatabaseResponse proto.InternalMessageInfo

func (m *MonitorDatabaseResponse) GetLevelDb() *LevelDb {
	if m != nil {
		return m.LevelDb
	}
	return nil
}

type LevelDb struct {
	Level                uint32   `protobuf:"varint,1,opt,name=level,proto3" json:"level,omitempty"`
	Lsp                  []*Lsp   `protobuf:"bytes,2,rep,name=lsp,proto3" json:"lsp,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LevelDb) Reset()         { *m = LevelDb{} }
func (m *LevelDb) String() string { return proto.CompactTextString(m) }
func (*LevelDb) ProtoMessage()    {}
func (*LevelDb) Descriptor() ([]byte, []int) {
	return fileDescriptor_07ca5a18eb6d27f6, []int{6}
}

func (m *LevelDb) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LevelDb.Unmarshal(m, b)
}
func (m *LevelDb) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LevelDb.Marshal(b, m, deterministic)
}
func (m *LevelDb) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LevelDb.Merge(m, src)
}
func (m *LevelDb) XXX_Size() int {
	return xxx_messageInfo_LevelDb.Size(m)
}
func (m *LevelDb) XXX_DiscardUnknown() {
	xxx_messageInfo_LevelDb.DiscardUnknown(m)
}

var xxx_messageInfo_LevelDb proto.InternalMessageInfo

func (m *LevelDb) GetLevel() uint32 {
	if m != nil {
		return m.Level
	}
	return 0
}

func (m *LevelDb) GetLsp() []*Lsp {
	if m != nil {
		return m.Lsp
	}
	return nil
}

type Lsp struct {
	DecodedCompleted     bool                  `protobuf:"varint,1,opt,name=decoded_completed,json=decodedCompleted,proto3" json:"decoded_completed,omitempty"`
	RawData              string                `protobuf:"bytes,2,opt,name=raw_data,json=rawData,proto3" json:"raw_data,omitempty"`
	LspId                string                `protobuf:"bytes,3,opt,name=lsp_id,json=lspId,proto3" json:"lsp_id,omitempty"`
	Checksum             uint32                `protobuf:"varint,4,opt,name=checksum,proto3" json:"checksum,omitempty"`
	RemainingLifetime    uint32                `protobuf:"varint,5,opt,name=remaining_lifetime,json=remainingLifetime,proto3" json:"remaining_lifetime,omitempty"`
	Sequence             uint32                `protobuf:"varint,6,opt,name=sequence,proto3" json:"sequence,omitempty"`
	Attributes           uint32                `protobuf:"varint,7,opt,name=attributes,proto3" json:"attributes,omitempty"`
	Ipv4Addresses        []string              `protobuf:"bytes,8,rep,name=ipv4_addresses,json=ipv4Addresses,proto3" json:"ipv4_addresses,omitempty"`
	Ipv6Addresses        []string              `protobuf:"bytes,9,rep,name=ipv6_addresses,json=ipv6Addresses,proto3" json:"ipv6_addresses,omitempty"`
	Ipv4TeRouterid       string                `protobuf:"bytes,10,opt,name=ipv4_te_routerid,json=ipv4TeRouterid,proto3" json:"ipv4_te_routerid,omitempty"`
	Ipv6TeRouterid       string                `protobuf:"bytes,11,opt,name=ipv6_te_routerid,json=ipv6TeRouterid,proto3" json:"ipv6_te_routerid,omitempty"`
	ProtocolSupported    []uint32              `protobuf:"varint,12,rep,packed,name=protocol_supported,json=protocolSupported,proto3" json:"protocol_supported,omitempty"`
	DynamicHostname      string                `protobuf:"bytes,13,opt,name=dynamic_hostname,json=dynamicHostname,proto3" json:"dynamic_hostname,omitempty"`
	Authentication       *Authentication       `protobuf:"bytes,14,opt,name=authentication,proto3" json:"authentication,omitempty"`
	MtEntries            *MtEntries            `protobuf:"bytes,15,opt,name=mt_entries,json=mtEntries,proto3" json:"mt_entries,omitempty"`
	RouterCapabilities   []*RouterCapabilities `protobuf:"bytes,16,rep,name=router_capabilities,json=routerCapabilities,proto3" json:"router_capabilities,omitempty"`
	NodeTags             *NodeTags             `protobuf:"bytes,17,opt,name=node_tags,json=nodeTags,proto3" json:"node_tags,omitempty"`
	Binary               []byte                `protobuf:"bytes,18,opt,name=binary,proto3" json:"binary,omitempty"`
	XXX_NoUnkeyedLiteral struct{}              `json:"-"`
	XXX_unrecognized     []byte                `json:"-"`
	XXX_sizecache        int32                 `json:"-"`
}

func (m *Lsp) Reset()         { *m = Lsp{} }
func (m *Lsp) String() string { return proto.CompactTextString(m) }
func (*Lsp) ProtoMessage()    {}
func (*Lsp) Descriptor() ([]byte, []int) {
	return fileDescriptor_07ca5a18eb6d27f6, []int{7}
}

func (m *Lsp) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Lsp.Unmarshal(m, b)
}
func (m *Lsp) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Lsp.Marshal(b, m, deterministic)
}
func (m *Lsp) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Lsp.Merge(m, src)
}
func (m *Lsp) XXX_Size() int {
	return xxx_messageInfo_Lsp.Size(m)
}
func (m *Lsp) XXX_DiscardUnknown() {
	xxx_messageInfo_Lsp.DiscardUnknown(m)
}

var xxx_messageInfo_Lsp proto.InternalMessageInfo

func (m *Lsp) GetDecodedCompleted() bool {
	if m != nil {
		return m.DecodedCompleted
	}
	return false
}

func (m *Lsp) GetRawData() string {
	if m != nil {
		return m.RawData
	}
	return ""
}

func (m *Lsp) GetLspId() string {
	if m != nil {
		return m.LspId
	}
	return ""
}

func (m *Lsp) GetChecksum() uint32 {
	if m != nil {
		return m.Checksum
	}
	return 0
}

func (m *Lsp) GetRemainingLifetime() uint32 {
	if m != nil {
		return m.RemainingLifetime
	}
	return 0
}

func (m *Lsp) GetSequence() uint32 {
	if m != nil {
		return m.Sequence
	}
	return 0
}

func (m *Lsp) GetAttributes() uint32 {
	if m != nil {
		return m.Attributes
	}
	return 0
}

func (m *Lsp) GetIpv4Addresses() []string {
	if m != nil {
		return m.Ipv4Addresses
	}
	return nil
}

func (m *Lsp) GetIpv6Addresses() []string {
	if m != nil {
		return m.Ipv6Addresses
	}
	return nil
}

func (m *Lsp) GetIpv4TeRouterid() string {
	if m != nil {
		return m.Ipv4TeRouterid
	}
	return ""
}

func (m *Lsp) GetIpv6TeRouterid() string {
	if m != nil {
		return m.Ipv6TeRouterid
	}
	return ""
}

func (m *Lsp) GetProtocolSupported() []uint32 {
	if m != nil {
		return m.ProtocolSupported
	}
	return nil
}

func (m *Lsp) GetDynamicHostname() string {
	if m != nil {
		return m.DynamicHostname
	}
	return ""
}

func (m *Lsp) GetAuthentication() *Authentication {
	if m != nil {
		return m.Authentication
	}
	return nil
}

func (m *Lsp) GetMtEntries() *MtEntries {
	if m != nil {
		return m.MtEntries
	}
	return nil
}

func (m *Lsp) GetRouterCapabilities() []*RouterCapabilities {
	if m != nil {
		return m.RouterCapabilities
	}
	return nil
}

func (m *Lsp) GetNodeTags() *NodeTags {
	if m != nil {
		return m.NodeTags
	}
	return nil
}

func (m *Lsp) GetBinary() []byte {
	if m != nil {
		return m.Binary
	}
	return nil
}

type Authentication struct {
	AuthenticationType   string   `protobuf:"bytes,1,opt,name=authentication_type,json=authenticationType,proto3" json:"authentication_type,omitempty"`
	AuthenticationKey    string   `protobuf:"bytes,2,opt,name=authentication_key,json=authenticationKey,proto3" json:"authentication_key,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Authentication) Reset()         { *m = Authentication{} }
func (m *Authentication) String() string { return proto.CompactTextString(m) }
func (*Authentication) ProtoMessage()    {}
func (*Authentication) Descriptor() ([]byte, []int) {
	return fileDescriptor_07ca5a18eb6d27f6, []int{8}
}

func (m *Authentication) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Authentication.Unmarshal(m, b)
}
func (m *Authentication) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Authentication.Marshal(b, m, deterministic)
}
func (m *Authentication) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Authentication.Merge(m, src)
}
func (m *Authentication) XXX_Size() int {
	return xxx_messageInfo_Authentication.Size(m)
}
func (m *Authentication) XXX_DiscardUnknown() {
	xxx_messageInfo_Authentication.DiscardUnknown(m)
}

var xxx_messageInfo_Authentication proto.InternalMessageInfo

func (m *Authentication) GetAuthenticationType() string {
	if m != nil {
		return m.AuthenticationType
	}
	return ""
}

func (m *Authentication) GetAuthenticationKey() string {
	if m != nil {
		return m.AuthenticationKey
	}
	return ""
}

type Topology struct {
	MtId                 uint32   `protobuf:"varint,1,opt,name=mt_id,json=mtId,proto3" json:"mt_id,omitempty"`
	Attributes           uint32   `protobuf:"varint,2,opt,name=attributes,proto3" json:"attributes,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Topology) Reset()         { *m = Topology{} }
func (m *Topology) String() string { return proto.CompactTextString(m) }
func (*Topology) ProtoMessage()    {}
func (*Topology) Descriptor() ([]byte, []int) {
	return fileDescriptor_07ca5a18eb6d27f6, []int{9}
}

func (m *Topology) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Topology.Unmarshal(m, b)
}
func (m *Topology) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Topology.Marshal(b, m, deterministic)
}
func (m *Topology) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Topology.Merge(m, src)
}
func (m *Topology) XXX_Size() int {
	return xxx_messageInfo_Topology.Size(m)
}
func (m *Topology) XXX_DiscardUnknown() {
	xxx_messageInfo_Topology.DiscardUnknown(m)
}

var xxx_messageInfo_Topology proto.InternalMessageInfo

func (m *Topology) GetMtId() uint32 {
	if m != nil {
		return m.MtId
	}
	return 0
}

func (m *Topology) GetAttributes() uint32 {
	if m != nil {
		return m.Attributes
	}
	return 0
}

type MtEntries struct {
	Topology             []*Topology `protobuf:"bytes,1,rep,name=topology,proto3" json:"topology,omitempty"`
	XXX_NoUnkeyedLiteral struct{}    `json:"-"`
	XXX_unrecognized     []byte      `json:"-"`
	XXX_sizecache        int32       `json:"-"`
}

func (m *MtEntries) Reset()         { *m = MtEntries{} }
func (m *MtEntries) String() string { return proto.CompactTextString(m) }
func (*MtEntries) ProtoMessage()    {}
func (*MtEntries) Descriptor() ([]byte, []int) {
	return fileDescriptor_07ca5a18eb6d27f6, []int{10}
}

func (m *MtEntries) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MtEntries.Unmarshal(m, b)
}
func (m *MtEntries) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MtEntries.Marshal(b, m, deterministic)
}
func (m *MtEntries) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MtEntries.Merge(m, src)
}
func (m *MtEntries) XXX_Size() int {
	return xxx_messageInfo_MtEntries.Size(m)
}
func (m *MtEntries) XXX_DiscardUnknown() {
	xxx_messageInfo_MtEntries.DiscardUnknown(m)
}

var xxx_messageInfo_MtEntries proto.InternalMessageInfo

func (m *MtEntries) GetTopology() []*Topology {
	if m != nil {
		return m.Topology
	}
	return nil
}

type RouterCapabilities struct {
	Flags                uint32   `protobuf:"varint,1,opt,name=flags,proto3" json:"flags,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *RouterCapabilities) Reset()         { *m = RouterCapabilities{} }
func (m *RouterCapabilities) String() string { return proto.CompactTextString(m) }
func (*RouterCapabilities) ProtoMessage()    {}
func (*RouterCapabilities) Descriptor() ([]byte, []int) {
	return fileDescriptor_07ca5a18eb6d27f6, []int{11}
}

func (m *RouterCapabilities) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RouterCapabilities.Unmarshal(m, b)
}
func (m *RouterCapabilities) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RouterCapabilities.Marshal(b, m, deterministic)
}
func (m *RouterCapabilities) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RouterCapabilities.Merge(m, src)
}
func (m *RouterCapabilities) XXX_Size() int {
	return xxx_messageInfo_RouterCapabilities.Size(m)
}
func (m *RouterCapabilities) XXX_DiscardUnknown() {
	xxx_messageInfo_RouterCapabilities.DiscardUnknown(m)
}

var xxx_messageInfo_RouterCapabilities proto.InternalMessageInfo

func (m *RouterCapabilities) GetFlags() uint32 {
	if m != nil {
		return m.Flags
	}
	return 0
}

type NodeTags struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *NodeTags) Reset()         { *m = NodeTags{} }
func (m *NodeTags) String() string { return proto.CompactTextString(m) }
func (*NodeTags) ProtoMessage()    {}
func (*NodeTags) Descriptor() ([]byte, []int) {
	return fileDescriptor_07ca5a18eb6d27f6, []int{12}
}

func (m *NodeTags) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_NodeTags.Unmarshal(m, b)
}
func (m *NodeTags) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_NodeTags.Marshal(b, m, deterministic)
}
func (m *NodeTags) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NodeTags.Merge(m, src)
}
func (m *NodeTags) XXX_Size() int {
	return xxx_messageInfo_NodeTags.Size(m)
}
func (m *NodeTags) XXX_DiscardUnknown() {
	xxx_messageInfo_NodeTags.DiscardUnknown(m)
}

var xxx_messageInfo_NodeTags proto.InternalMessageInfo

type Global struct {
	SystemId             string   `protobuf:"bytes,1,opt,name=system_id,json=systemId,proto3" json:"system_id,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Global) Reset()         { *m = Global{} }
func (m *Global) String() string { return proto.CompactTextString(m) }
func (*Global) ProtoMessage()    {}
func (*Global) Descriptor() ([]byte, []int) {
	return fileDescriptor_07ca5a18eb6d27f6, []int{13}
}

func (m *Global) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Global.Unmarshal(m, b)
}
func (m *Global) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Global.Marshal(b, m, deterministic)
}
func (m *Global) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Global.Merge(m, src)
}
func (m *Global) XXX_Size() int {
	return xxx_messageInfo_Global.Size(m)
}
func (m *Global) XXX_DiscardUnknown() {
	xxx_messageInfo_Global.DiscardUnknown(m)
}

var xxx_messageInfo_Global proto.InternalMessageInfo

func (m *Global) GetSystemId() string {
	if m != nil {
		return m.SystemId
	}
	return ""
}

func init() {
	proto.RegisterType((*StartIsisRequest)(nil), "goisisapi.StartIsisRequest")
	proto.RegisterType((*StopIsisRequest)(nil), "goisisapi.StopIsisRequest")
	proto.RegisterType((*GetDatabaseRequest)(nil), "goisisapi.GetDatabaseRequest")
	proto.RegisterType((*GetDatabaseResponse)(nil), "goisisapi.GetDatabaseResponse")
	proto.RegisterType((*MonitorDatabaseRequest)(nil), "goisisapi.MonitorDatabaseRequest")
	proto.RegisterType((*MonitorDatabaseResponse)(nil), "goisisapi.MonitorDatabaseResponse")
	proto.RegisterType((*LevelDb)(nil), "goisisapi.LevelDb")
	proto.RegisterType((*Lsp)(nil), "goisisapi.Lsp")
	proto.RegisterType((*Authentication)(nil), "goisisapi.Authentication")
	proto.RegisterType((*Topology)(nil), "goisisapi.Topology")
	proto.RegisterType((*MtEntries)(nil), "goisisapi.MtEntries")
	proto.RegisterType((*RouterCapabilities)(nil), "goisisapi.RouterCapabilities")
	proto.RegisterType((*NodeTags)(nil), "goisisapi.NodeTags")
	proto.RegisterType((*Global)(nil), "goisisapi.Global")
}

func init() { proto.RegisterFile("goisis.proto", fileDescriptor_07ca5a18eb6d27f6) }

var fileDescriptor_07ca5a18eb6d27f6 = []byte{
	// 827 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x7c, 0x54, 0x4d, 0x6f, 0xdb, 0x46,
	0x10, 0x85, 0xac, 0x58, 0x26, 0xc7, 0xb6, 0x2c, 0x8d, 0x1c, 0x97, 0x91, 0xd1, 0x40, 0x25, 0x10,
	0x40, 0x69, 0x61, 0x39, 0x70, 0x0a, 0x9f, 0xfa, 0x25, 0x24, 0x81, 0x63, 0xd4, 0xc9, 0x61, 0xed,
	0x53, 0x2f, 0xc4, 0x92, 0x1c, 0xcb, 0x8b, 0x90, 0xdc, 0x2d, 0x77, 0x95, 0x80, 0xbf, 0xac, 0xbf,
	0xad, 0xb7, 0x82, 0x4b, 0x52, 0x25, 0xe5, 0xa6, 0x37, 0xce, 0x7b, 0x6f, 0x66, 0x67, 0x87, 0xb3,
	0x0f, 0x0e, 0x56, 0x52, 0x68, 0xa1, 0x17, 0x2a, 0x97, 0x46, 0xa2, 0x5b, 0x45, 0x5c, 0x89, 0xe9,
	0xe9, 0x4a, 0xca, 0x55, 0x42, 0xe7, 0x96, 0x08, 0xd7, 0xf7, 0xe7, 0x94, 0x2a, 0x53, 0x54, 0x3a,
	0xff, 0x67, 0x18, 0xdd, 0x1a, 0x9e, 0x9b, 0x6b, 0x2d, 0x34, 0xa3, 0x3f, 0xd7, 0xa4, 0x0d, 0xbe,
	0x84, 0xc1, 0x2a, 0x91, 0x21, 0x4f, 0xbc, 0xde, 0xac, 0x37, 0xdf, 0xbf, 0x18, 0x2f, 0x36, 0xc5,
	0x16, 0x57, 0x96, 0x60, 0xb5, 0xc0, 0x1f, 0xc3, 0xd1, 0xad, 0x91, 0xaa, 0x95, 0xed, 0x1f, 0x03,
	0x5e, 0x91, 0x79, 0xcb, 0x0d, 0x0f, 0xb9, 0xa6, 0x06, 0x7d, 0x0a, 0x93, 0x0e, 0xaa, 0x95, 0xcc,
	0x34, 0xf9, 0x1e, 0x9c, 0x7c, 0x90, 0x99, 0x30, 0x32, 0xdf, 0x4e, 0x78, 0x0f, 0xdf, 0x3c, 0x62,
	0xaa, 0x24, 0x3c, 0x03, 0x27, 0xa1, 0xcf, 0x94, 0x04, 0x71, 0x58, 0x77, 0x88, 0xad, 0x0e, 0x6f,
	0x4a, 0xea, 0x6d, 0xc8, 0xf6, 0x92, 0xea, 0xc3, 0x5f, 0xc2, 0x5e, 0x8d, 0xe1, 0x31, 0xec, 0x5a,
	0xd4, 0xa6, 0x1d, 0xb2, 0x2a, 0xc0, 0x19, 0xf4, 0x13, 0xad, 0xbc, 0x9d, 0x59, 0x7f, 0xbe, 0x7f,
	0x31, 0x6c, 0x97, 0xd2, 0x8a, 0x95, 0x94, 0xff, 0xf7, 0x2e, 0xf4, 0x6f, 0xb4, 0xc2, 0x1f, 0x60,
	0x1c, 0x53, 0x24, 0x63, 0x8a, 0x83, 0x48, 0xa6, 0x2a, 0x21, 0x43, 0xb1, 0xad, 0xe5, 0xb0, 0x51,
	0x4d, 0xbc, 0x69, 0x70, 0x7c, 0x06, 0x4e, 0xce, 0xbf, 0x04, 0x31, 0x37, 0xdc, 0xdb, 0x99, 0xf5,
	0xe6, 0x2e, 0xdb, 0xcb, 0xf9, 0x97, 0xf2, 0x36, 0xf8, 0x14, 0x06, 0x89, 0x56, 0x81, 0x88, 0xbd,
	0xbe, 0x25, 0x76, 0x13, 0xad, 0xae, 0x63, 0x9c, 0x82, 0x13, 0x3d, 0x50, 0xf4, 0x49, 0xaf, 0x53,
	0xef, 0x89, 0xed, 0x70, 0x13, 0xe3, 0x19, 0x60, 0x4e, 0x29, 0x17, 0x99, 0xc8, 0x56, 0x41, 0x22,
	0xee, 0xc9, 0x88, 0x94, 0xbc, 0x5d, 0xab, 0x1a, 0x6f, 0x98, 0x9b, 0x9a, 0x28, 0x4b, 0xe9, 0x72,
	0x92, 0x59, 0x44, 0xde, 0xa0, 0x2a, 0xd5, 0xc4, 0xf8, 0x1c, 0x80, 0x1b, 0x93, 0x8b, 0x70, 0x6d,
	0x48, 0x7b, 0x7b, 0x96, 0x6d, 0x21, 0xf8, 0x02, 0x86, 0x42, 0x7d, 0xfe, 0x31, 0xe0, 0x71, 0x9c,
	0x93, 0xd6, 0xa4, 0x3d, 0x67, 0xd6, 0x9f, 0xbb, 0xec, 0xb0, 0x44, 0x97, 0x0d, 0x58, 0xcb, 0x2e,
	0x5b, 0x32, 0x77, 0x23, 0xbb, 0xfc, 0x57, 0x36, 0x87, 0x91, 0xad, 0x66, 0x28, 0xc8, 0xe5, 0xda,
	0x50, 0x2e, 0x62, 0x0f, 0xec, 0xad, 0xed, 0x29, 0x77, 0xc4, 0x6a, 0xb4, 0x56, 0x5e, 0x76, 0x94,
	0xfb, 0x1b, 0xe5, 0x65, 0x4b, 0x79, 0x06, 0x68, 0xd7, 0x37, 0x92, 0x49, 0xa0, 0xd7, 0x4a, 0xc9,
	0xbc, 0xfc, 0x11, 0x07, 0xb3, 0x7e, 0x39, 0x8c, 0x86, 0xb9, 0x6d, 0x08, 0x7c, 0x09, 0xa3, 0xb8,
	0xc8, 0x78, 0x2a, 0xa2, 0xe0, 0x41, 0x6a, 0x93, 0xf1, 0x94, 0xbc, 0x43, 0x5b, 0xf8, 0xa8, 0xc6,
	0xdf, 0xd7, 0x30, 0x2e, 0x61, 0xc8, 0xd7, 0xe6, 0x81, 0x32, 0x23, 0x22, 0x6e, 0x84, 0xcc, 0xbc,
	0xa1, 0xdd, 0xb0, 0x67, 0xad, 0xb5, 0x58, 0x76, 0x04, 0x6c, 0x2b, 0x01, 0x5f, 0x03, 0xa4, 0x26,
	0xa0, 0xcc, 0xe4, 0x82, 0xb4, 0x77, 0x64, 0xd3, 0x8f, 0x5b, 0xe9, 0x1f, 0xcc, 0xbb, 0x8a, 0x63,
	0x6e, 0xda, 0x7c, 0xe2, 0x47, 0x98, 0x54, 0x77, 0x0e, 0x22, 0xae, 0x78, 0x28, 0x12, 0x61, 0xca,
	0xec, 0x91, 0xdd, 0xc9, 0x6f, 0x5b, 0xd9, 0xd5, 0x0c, 0xde, 0xb4, 0x44, 0x0c, 0xf3, 0x47, 0x18,
	0xbe, 0x02, 0x37, 0x93, 0x31, 0x05, 0x86, 0xaf, 0xb4, 0x37, 0xb6, 0x3d, 0x4c, 0x5a, 0x55, 0x3e,
	0xca, 0x98, 0xee, 0xf8, 0x4a, 0x33, 0x27, 0xab, 0xbf, 0xf0, 0x04, 0x06, 0xa1, 0xc8, 0x78, 0x5e,
	0x78, 0x38, 0xeb, 0xcd, 0x0f, 0x58, 0x1d, 0xf9, 0x0a, 0x86, 0xdd, 0x0b, 0xe3, 0x39, 0x4c, 0xba,
	0x57, 0x0e, 0x4c, 0xa1, 0xc8, 0xbe, 0x03, 0x97, 0x61, 0x97, 0xba, 0x2b, 0x54, 0xf9, 0x60, 0xb7,
	0xd0, 0xe0, 0x13, 0x15, 0xf5, 0x9b, 0x18, 0x77, 0x99, 0xdf, 0xa9, 0xf0, 0x7f, 0x05, 0xe7, 0x4e,
	0x2a, 0x99, 0xc8, 0x55, 0x81, 0x13, 0xd8, 0x4d, 0x4d, 0xf9, 0x50, 0xaa, 0x17, 0xfb, 0x24, 0x35,
	0xd7, 0xf1, 0xd6, 0x02, 0xef, 0x6c, 0x2f, 0xb0, 0xff, 0x13, 0xb8, 0x9b, 0x21, 0xe3, 0x39, 0x38,
	0xa6, 0xae, 0xe6, 0xf5, 0xec, 0x38, 0xdb, 0x83, 0x68, 0x0e, 0x62, 0x1b, 0x91, 0xff, 0x3d, 0xe0,
	0xe3, 0x21, 0x97, 0xd6, 0x71, 0x9f, 0x94, 0xc3, 0xac, 0xad, 0xc3, 0x06, 0x3e, 0x80, 0xd3, 0x8c,
	0xd2, 0x7f, 0x01, 0x83, 0xca, 0x1d, 0xf1, 0x14, 0x5c, 0x5d, 0x68, 0x43, 0x69, 0xd3, 0xb8, 0xcb,
	0x9c, 0x0a, 0xb8, 0x8e, 0x2f, 0xfe, 0xda, 0x01, 0xf7, 0xca, 0x9e, 0xbf, 0x54, 0x02, 0x7f, 0x03,
	0x77, 0xe3, 0xbf, 0x78, 0xda, 0x6a, 0x6c, 0xdb, 0x95, 0xa7, 0x27, 0x8b, 0xca, 0xc7, 0x17, 0x8d,
	0x8f, 0x2f, 0xde, 0x95, 0x3e, 0x8e, 0xbf, 0x80, 0xd3, 0x58, 0x30, 0x4e, 0x3b, 0x05, 0x3a, 0xbe,
	0xfc, 0xd5, 0xfc, 0x1b, 0xd8, 0x6f, 0x39, 0x33, 0xb6, 0x77, 0xed, 0xb1, 0x8f, 0x4f, 0x9f, 0x7f,
	0x8d, 0xae, 0xbd, 0xf9, 0x0f, 0x38, 0xda, 0xb2, 0x6d, 0xfc, 0xae, 0xbd, 0xfb, 0xff, 0x69, 0xf6,
	0x53, 0xff, 0xff, 0x24, 0x55, 0xe5, 0x57, 0xbd, 0x70, 0x60, 0x3b, 0x7f, 0xfd, 0x4f, 0x00, 0x00,
	0x00, 0xff, 0xff, 0x11, 0x3f, 0x0b, 0xe2, 0xea, 0x06, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// GoisisApiClient is the client API for GoisisApi service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type GoisisApiClient interface {
	StartIsis(ctx context.Context, in *StartIsisRequest, opts ...grpc.CallOption) (*empty.Empty, error)
	StopIsis(ctx context.Context, in *StopIsisRequest, opts ...grpc.CallOption) (*empty.Empty, error)
	GetDatabase(ctx context.Context, in *GetDatabaseRequest, opts ...grpc.CallOption) (*GetDatabaseResponse, error)
	MonitorDatabase(ctx context.Context, in *MonitorDatabaseRequest, opts ...grpc.CallOption) (GoisisApi_MonitorDatabaseClient, error)
}

type goisisApiClient struct {
	cc *grpc.ClientConn
}

func NewGoisisApiClient(cc *grpc.ClientConn) GoisisApiClient {
	return &goisisApiClient{cc}
}

func (c *goisisApiClient) StartIsis(ctx context.Context, in *StartIsisRequest, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/goisisapi.GoisisApi/StartIsis", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *goisisApiClient) StopIsis(ctx context.Context, in *StopIsisRequest, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/goisisapi.GoisisApi/StopIsis", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *goisisApiClient) GetDatabase(ctx context.Context, in *GetDatabaseRequest, opts ...grpc.CallOption) (*GetDatabaseResponse, error) {
	out := new(GetDatabaseResponse)
	err := c.cc.Invoke(ctx, "/goisisapi.GoisisApi/GetDatabase", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *goisisApiClient) MonitorDatabase(ctx context.Context, in *MonitorDatabaseRequest, opts ...grpc.CallOption) (GoisisApi_MonitorDatabaseClient, error) {
	stream, err := c.cc.NewStream(ctx, &_GoisisApi_serviceDesc.Streams[0], "/goisisapi.GoisisApi/MonitorDatabase", opts...)
	if err != nil {
		return nil, err
	}
	x := &goisisApiMonitorDatabaseClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type GoisisApi_MonitorDatabaseClient interface {
	Recv() (*MonitorDatabaseResponse, error)
	grpc.ClientStream
}

type goisisApiMonitorDatabaseClient struct {
	grpc.ClientStream
}

func (x *goisisApiMonitorDatabaseClient) Recv() (*MonitorDatabaseResponse, error) {
	m := new(MonitorDatabaseResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// GoisisApiServer is the server API for GoisisApi service.
type GoisisApiServer interface {
	StartIsis(context.Context, *StartIsisRequest) (*empty.Empty, error)
	StopIsis(context.Context, *StopIsisRequest) (*empty.Empty, error)
	GetDatabase(context.Context, *GetDatabaseRequest) (*GetDatabaseResponse, error)
	MonitorDatabase(*MonitorDatabaseRequest, GoisisApi_MonitorDatabaseServer) error
}

func RegisterGoisisApiServer(s *grpc.Server, srv GoisisApiServer) {
	s.RegisterService(&_GoisisApi_serviceDesc, srv)
}

func _GoisisApi_StartIsis_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(StartIsisRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GoisisApiServer).StartIsis(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/goisisapi.GoisisApi/StartIsis",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GoisisApiServer).StartIsis(ctx, req.(*StartIsisRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _GoisisApi_StopIsis_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(StopIsisRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GoisisApiServer).StopIsis(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/goisisapi.GoisisApi/StopIsis",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GoisisApiServer).StopIsis(ctx, req.(*StopIsisRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _GoisisApi_GetDatabase_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetDatabaseRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GoisisApiServer).GetDatabase(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/goisisapi.GoisisApi/GetDatabase",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GoisisApiServer).GetDatabase(ctx, req.(*GetDatabaseRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _GoisisApi_MonitorDatabase_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(MonitorDatabaseRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(GoisisApiServer).MonitorDatabase(m, &goisisApiMonitorDatabaseServer{stream})
}

type GoisisApi_MonitorDatabaseServer interface {
	Send(*MonitorDatabaseResponse) error
	grpc.ServerStream
}

type goisisApiMonitorDatabaseServer struct {
	grpc.ServerStream
}

func (x *goisisApiMonitorDatabaseServer) Send(m *MonitorDatabaseResponse) error {
	return x.ServerStream.SendMsg(m)
}

var _GoisisApi_serviceDesc = grpc.ServiceDesc{
	ServiceName: "goisisapi.GoisisApi",
	HandlerType: (*GoisisApiServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "StartIsis",
			Handler:    _GoisisApi_StartIsis_Handler,
		},
		{
			MethodName: "StopIsis",
			Handler:    _GoisisApi_StopIsis_Handler,
		},
		{
			MethodName: "GetDatabase",
			Handler:    _GoisisApi_GetDatabase_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "MonitorDatabase",
			Handler:       _GoisisApi_MonitorDatabase_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "goisis.proto",
}