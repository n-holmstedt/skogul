// Code generated by protoc-gen-go. DO NOT EDIT.
// source: rpd_loc_rib_oc.proto

package telemetry

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
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
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type LocalRoutesLocRib struct {
	StaticRoutes         *LocalRoutesLocRibStaticRoutesType    `protobuf:"bytes,151,opt,name=static_routes,json=staticRoutes" json:"static_routes,omitempty"`
	LocalAggregates      *LocalRoutesLocRibLocalAggregatesType `protobuf:"bytes,152,opt,name=local_aggregates,json=localAggregates" json:"local_aggregates,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                              `json:"-"`
	XXX_unrecognized     []byte                                `json:"-"`
	XXX_sizecache        int32                                 `json:"-"`
}

func (m *LocalRoutesLocRib) Reset()         { *m = LocalRoutesLocRib{} }
func (m *LocalRoutesLocRib) String() string { return proto.CompactTextString(m) }
func (*LocalRoutesLocRib) ProtoMessage()    {}
func (*LocalRoutesLocRib) Descriptor() ([]byte, []int) {
	return fileDescriptor_b9ea89688009886c, []int{0}
}

func (m *LocalRoutesLocRib) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LocalRoutesLocRib.Unmarshal(m, b)
}
func (m *LocalRoutesLocRib) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LocalRoutesLocRib.Marshal(b, m, deterministic)
}
func (m *LocalRoutesLocRib) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LocalRoutesLocRib.Merge(m, src)
}
func (m *LocalRoutesLocRib) XXX_Size() int {
	return xxx_messageInfo_LocalRoutesLocRib.Size(m)
}
func (m *LocalRoutesLocRib) XXX_DiscardUnknown() {
	xxx_messageInfo_LocalRoutesLocRib.DiscardUnknown(m)
}

var xxx_messageInfo_LocalRoutesLocRib proto.InternalMessageInfo

func (m *LocalRoutesLocRib) GetStaticRoutes() *LocalRoutesLocRibStaticRoutesType {
	if m != nil {
		return m.StaticRoutes
	}
	return nil
}

func (m *LocalRoutesLocRib) GetLocalAggregates() *LocalRoutesLocRibLocalAggregatesType {
	if m != nil {
		return m.LocalAggregates
	}
	return nil
}

type LocalRoutesLocRibStaticRoutesType struct {
	Static               []*LocalRoutesLocRibStaticRoutesTypeStaticList `protobuf:"bytes,51,rep,name=static" json:"static,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                                       `json:"-"`
	XXX_unrecognized     []byte                                         `json:"-"`
	XXX_sizecache        int32                                          `json:"-"`
}

func (m *LocalRoutesLocRibStaticRoutesType) Reset()         { *m = LocalRoutesLocRibStaticRoutesType{} }
func (m *LocalRoutesLocRibStaticRoutesType) String() string { return proto.CompactTextString(m) }
func (*LocalRoutesLocRibStaticRoutesType) ProtoMessage()    {}
func (*LocalRoutesLocRibStaticRoutesType) Descriptor() ([]byte, []int) {
	return fileDescriptor_b9ea89688009886c, []int{0, 0}
}

func (m *LocalRoutesLocRibStaticRoutesType) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LocalRoutesLocRibStaticRoutesType.Unmarshal(m, b)
}
func (m *LocalRoutesLocRibStaticRoutesType) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LocalRoutesLocRibStaticRoutesType.Marshal(b, m, deterministic)
}
func (m *LocalRoutesLocRibStaticRoutesType) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LocalRoutesLocRibStaticRoutesType.Merge(m, src)
}
func (m *LocalRoutesLocRibStaticRoutesType) XXX_Size() int {
	return xxx_messageInfo_LocalRoutesLocRibStaticRoutesType.Size(m)
}
func (m *LocalRoutesLocRibStaticRoutesType) XXX_DiscardUnknown() {
	xxx_messageInfo_LocalRoutesLocRibStaticRoutesType.DiscardUnknown(m)
}

var xxx_messageInfo_LocalRoutesLocRibStaticRoutesType proto.InternalMessageInfo

func (m *LocalRoutesLocRibStaticRoutesType) GetStatic() []*LocalRoutesLocRibStaticRoutesTypeStaticList {
	if m != nil {
		return m.Static
	}
	return nil
}

type LocalRoutesLocRibStaticRoutesTypeStaticList struct {
	Prefix               *string                                                  `protobuf:"bytes,51,opt,name=prefix" json:"prefix,omitempty"`
	State                *LocalRoutesLocRibStaticRoutesTypeStaticListStateType    `protobuf:"bytes,151,opt,name=state" json:"state,omitempty"`
	NextHops             *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsType `protobuf:"bytes,152,opt,name=next_hops,json=nextHops" json:"next_hops,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                                                 `json:"-"`
	XXX_unrecognized     []byte                                                   `json:"-"`
	XXX_sizecache        int32                                                    `json:"-"`
}

func (m *LocalRoutesLocRibStaticRoutesTypeStaticList) Reset() {
	*m = LocalRoutesLocRibStaticRoutesTypeStaticList{}
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticList) String() string {
	return proto.CompactTextString(m)
}
func (*LocalRoutesLocRibStaticRoutesTypeStaticList) ProtoMessage() {}
func (*LocalRoutesLocRibStaticRoutesTypeStaticList) Descriptor() ([]byte, []int) {
	return fileDescriptor_b9ea89688009886c, []int{0, 0, 0}
}

func (m *LocalRoutesLocRibStaticRoutesTypeStaticList) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticList.Unmarshal(m, b)
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticList) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticList.Marshal(b, m, deterministic)
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticList) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticList.Merge(m, src)
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticList) XXX_Size() int {
	return xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticList.Size(m)
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticList) XXX_DiscardUnknown() {
	xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticList.DiscardUnknown(m)
}

var xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticList proto.InternalMessageInfo

func (m *LocalRoutesLocRibStaticRoutesTypeStaticList) GetPrefix() string {
	if m != nil && m.Prefix != nil {
		return *m.Prefix
	}
	return ""
}

func (m *LocalRoutesLocRibStaticRoutesTypeStaticList) GetState() *LocalRoutesLocRibStaticRoutesTypeStaticListStateType {
	if m != nil {
		return m.State
	}
	return nil
}

func (m *LocalRoutesLocRibStaticRoutesTypeStaticList) GetNextHops() *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsType {
	if m != nil {
		return m.NextHops
	}
	return nil
}

type LocalRoutesLocRibStaticRoutesTypeStaticListStateType struct {
	Prefix               *string  `protobuf:"bytes,51,opt,name=prefix" json:"prefix,omitempty"`
	SetTag               *string  `protobuf:"bytes,52,opt,name=set_tag,json=setTag" json:"set_tag,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LocalRoutesLocRibStaticRoutesTypeStaticListStateType) Reset() {
	*m = LocalRoutesLocRibStaticRoutesTypeStaticListStateType{}
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListStateType) String() string {
	return proto.CompactTextString(m)
}
func (*LocalRoutesLocRibStaticRoutesTypeStaticListStateType) ProtoMessage() {}
func (*LocalRoutesLocRibStaticRoutesTypeStaticListStateType) Descriptor() ([]byte, []int) {
	return fileDescriptor_b9ea89688009886c, []int{0, 0, 0, 0}
}

func (m *LocalRoutesLocRibStaticRoutesTypeStaticListStateType) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListStateType.Unmarshal(m, b)
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListStateType) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListStateType.Marshal(b, m, deterministic)
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListStateType) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListStateType.Merge(m, src)
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListStateType) XXX_Size() int {
	return xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListStateType.Size(m)
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListStateType) XXX_DiscardUnknown() {
	xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListStateType.DiscardUnknown(m)
}

var xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListStateType proto.InternalMessageInfo

func (m *LocalRoutesLocRibStaticRoutesTypeStaticListStateType) GetPrefix() string {
	if m != nil && m.Prefix != nil {
		return *m.Prefix
	}
	return ""
}

func (m *LocalRoutesLocRibStaticRoutesTypeStaticListStateType) GetSetTag() string {
	if m != nil && m.SetTag != nil {
		return *m.SetTag
	}
	return ""
}

type LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsType struct {
	NextHop              []*LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopList `protobuf:"bytes,51,rep,name=next_hop,json=nextHop" json:"next_hop,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                                                              `json:"-"`
	XXX_unrecognized     []byte                                                                `json:"-"`
	XXX_sizecache        int32                                                                 `json:"-"`
}

func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsType) Reset() {
	*m = LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsType{}
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsType) String() string {
	return proto.CompactTextString(m)
}
func (*LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsType) ProtoMessage() {}
func (*LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsType) Descriptor() ([]byte, []int) {
	return fileDescriptor_b9ea89688009886c, []int{0, 0, 0, 1}
}

func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsType) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsType.Unmarshal(m, b)
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsType) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsType.Marshal(b, m, deterministic)
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsType) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsType.Merge(m, src)
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsType) XXX_Size() int {
	return xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsType.Size(m)
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsType) XXX_DiscardUnknown() {
	xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsType.DiscardUnknown(m)
}

var xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsType proto.InternalMessageInfo

func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsType) GetNextHop() []*LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopList {
	if m != nil {
		return m.NextHop
	}
	return nil
}

type LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopList struct {
	Index                *string                                                                             `protobuf:"bytes,51,opt,name=index" json:"index,omitempty"`
	State                *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListStateType        `protobuf:"bytes,151,opt,name=state" json:"state,omitempty"`
	InterfaceRef         *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefType `protobuf:"bytes,152,opt,name=interface_ref,json=interfaceRef" json:"interface_ref,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                                                                            `json:"-"`
	XXX_unrecognized     []byte                                                                              `json:"-"`
	XXX_sizecache        int32                                                                               `json:"-"`
}

func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopList) Reset() {
	*m = LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopList{}
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopList) String() string {
	return proto.CompactTextString(m)
}
func (*LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopList) ProtoMessage() {}
func (*LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopList) Descriptor() ([]byte, []int) {
	return fileDescriptor_b9ea89688009886c, []int{0, 0, 0, 1, 0}
}

func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopList) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopList.Unmarshal(m, b)
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopList) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopList.Marshal(b, m, deterministic)
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopList) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopList.Merge(m, src)
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopList) XXX_Size() int {
	return xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopList.Size(m)
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopList) XXX_DiscardUnknown() {
	xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopList.DiscardUnknown(m)
}

var xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopList proto.InternalMessageInfo

func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopList) GetIndex() string {
	if m != nil && m.Index != nil {
		return *m.Index
	}
	return ""
}

func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopList) GetState() *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListStateType {
	if m != nil {
		return m.State
	}
	return nil
}

func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopList) GetInterfaceRef() *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefType {
	if m != nil {
		return m.InterfaceRef
	}
	return nil
}

type LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListStateType struct {
	Index                *string  `protobuf:"bytes,51,opt,name=index" json:"index,omitempty"`
	NextHop              *string  `protobuf:"bytes,52,opt,name=next_hop,json=nextHop" json:"next_hop,omitempty"`
	Metric               *uint32  `protobuf:"varint,53,opt,name=metric" json:"metric,omitempty"`
	Recurse              *bool    `protobuf:"varint,54,opt,name=recurse" json:"recurse,omitempty"`
	SetTag               *string  `protobuf:"bytes,55,opt,name=set_tag,json=setTag" json:"set_tag,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListStateType) Reset() {
	*m = LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListStateType{}
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListStateType) String() string {
	return proto.CompactTextString(m)
}
func (*LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListStateType) ProtoMessage() {}
func (*LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListStateType) Descriptor() ([]byte, []int) {
	return fileDescriptor_b9ea89688009886c, []int{0, 0, 0, 1, 0, 0}
}

func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListStateType) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListStateType.Unmarshal(m, b)
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListStateType) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListStateType.Marshal(b, m, deterministic)
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListStateType) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListStateType.Merge(m, src)
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListStateType) XXX_Size() int {
	return xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListStateType.Size(m)
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListStateType) XXX_DiscardUnknown() {
	xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListStateType.DiscardUnknown(m)
}

var xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListStateType proto.InternalMessageInfo

func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListStateType) GetIndex() string {
	if m != nil && m.Index != nil {
		return *m.Index
	}
	return ""
}

func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListStateType) GetNextHop() string {
	if m != nil && m.NextHop != nil {
		return *m.NextHop
	}
	return ""
}

func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListStateType) GetMetric() uint32 {
	if m != nil && m.Metric != nil {
		return *m.Metric
	}
	return 0
}

func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListStateType) GetRecurse() bool {
	if m != nil && m.Recurse != nil {
		return *m.Recurse
	}
	return false
}

func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListStateType) GetSetTag() string {
	if m != nil && m.SetTag != nil {
		return *m.SetTag
	}
	return ""
}

type LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefType struct {
	State                *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefTypeStateType `protobuf:"bytes,151,opt,name=state" json:"state,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                                                                                     `json:"-"`
	XXX_unrecognized     []byte                                                                                       `json:"-"`
	XXX_sizecache        int32                                                                                        `json:"-"`
}

func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefType) Reset() {
	*m = LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefType{}
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefType) String() string {
	return proto.CompactTextString(m)
}
func (*LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefType) ProtoMessage() {
}
func (*LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefType) Descriptor() ([]byte, []int) {
	return fileDescriptor_b9ea89688009886c, []int{0, 0, 0, 1, 0, 1}
}

func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefType) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefType.Unmarshal(m, b)
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefType) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefType.Marshal(b, m, deterministic)
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefType) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefType.Merge(m, src)
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefType) XXX_Size() int {
	return xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefType.Size(m)
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefType) XXX_DiscardUnknown() {
	xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefType.DiscardUnknown(m)
}

var xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefType proto.InternalMessageInfo

func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefType) GetState() *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefTypeStateType {
	if m != nil {
		return m.State
	}
	return nil
}

type LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefTypeStateType struct {
	Interface            *string  `protobuf:"bytes,51,opt,name=interface" json:"interface,omitempty"`
	Subinterface         *uint32  `protobuf:"varint,52,opt,name=subinterface" json:"subinterface,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefTypeStateType) Reset() {
	*m = LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefTypeStateType{}
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefTypeStateType) String() string {
	return proto.CompactTextString(m)
}
func (*LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefTypeStateType) ProtoMessage() {
}
func (*LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefTypeStateType) Descriptor() ([]byte, []int) {
	return fileDescriptor_b9ea89688009886c, []int{0, 0, 0, 1, 0, 1, 0}
}

func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefTypeStateType) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefTypeStateType.Unmarshal(m, b)
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefTypeStateType) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefTypeStateType.Marshal(b, m, deterministic)
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefTypeStateType) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefTypeStateType.Merge(m, src)
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefTypeStateType) XXX_Size() int {
	return xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefTypeStateType.Size(m)
}
func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefTypeStateType) XXX_DiscardUnknown() {
	xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefTypeStateType.DiscardUnknown(m)
}

var xxx_messageInfo_LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefTypeStateType proto.InternalMessageInfo

func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefTypeStateType) GetInterface() string {
	if m != nil && m.Interface != nil {
		return *m.Interface
	}
	return ""
}

func (m *LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefTypeStateType) GetSubinterface() uint32 {
	if m != nil && m.Subinterface != nil {
		return *m.Subinterface
	}
	return 0
}

type LocalRoutesLocRibLocalAggregatesType struct {
	Aggregate            []*LocalRoutesLocRibLocalAggregatesTypeAggregateList `protobuf:"bytes,51,rep,name=aggregate" json:"aggregate,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                                             `json:"-"`
	XXX_unrecognized     []byte                                               `json:"-"`
	XXX_sizecache        int32                                                `json:"-"`
}

func (m *LocalRoutesLocRibLocalAggregatesType) Reset()         { *m = LocalRoutesLocRibLocalAggregatesType{} }
func (m *LocalRoutesLocRibLocalAggregatesType) String() string { return proto.CompactTextString(m) }
func (*LocalRoutesLocRibLocalAggregatesType) ProtoMessage()    {}
func (*LocalRoutesLocRibLocalAggregatesType) Descriptor() ([]byte, []int) {
	return fileDescriptor_b9ea89688009886c, []int{0, 1}
}

func (m *LocalRoutesLocRibLocalAggregatesType) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LocalRoutesLocRibLocalAggregatesType.Unmarshal(m, b)
}
func (m *LocalRoutesLocRibLocalAggregatesType) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LocalRoutesLocRibLocalAggregatesType.Marshal(b, m, deterministic)
}
func (m *LocalRoutesLocRibLocalAggregatesType) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LocalRoutesLocRibLocalAggregatesType.Merge(m, src)
}
func (m *LocalRoutesLocRibLocalAggregatesType) XXX_Size() int {
	return xxx_messageInfo_LocalRoutesLocRibLocalAggregatesType.Size(m)
}
func (m *LocalRoutesLocRibLocalAggregatesType) XXX_DiscardUnknown() {
	xxx_messageInfo_LocalRoutesLocRibLocalAggregatesType.DiscardUnknown(m)
}

var xxx_messageInfo_LocalRoutesLocRibLocalAggregatesType proto.InternalMessageInfo

func (m *LocalRoutesLocRibLocalAggregatesType) GetAggregate() []*LocalRoutesLocRibLocalAggregatesTypeAggregateList {
	if m != nil {
		return m.Aggregate
	}
	return nil
}

type LocalRoutesLocRibLocalAggregatesTypeAggregateList struct {
	Prefix               *string                                                     `protobuf:"bytes,51,opt,name=prefix" json:"prefix,omitempty"`
	State                *LocalRoutesLocRibLocalAggregatesTypeAggregateListStateType `protobuf:"bytes,151,opt,name=state" json:"state,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                                                    `json:"-"`
	XXX_unrecognized     []byte                                                      `json:"-"`
	XXX_sizecache        int32                                                       `json:"-"`
}

func (m *LocalRoutesLocRibLocalAggregatesTypeAggregateList) Reset() {
	*m = LocalRoutesLocRibLocalAggregatesTypeAggregateList{}
}
func (m *LocalRoutesLocRibLocalAggregatesTypeAggregateList) String() string {
	return proto.CompactTextString(m)
}
func (*LocalRoutesLocRibLocalAggregatesTypeAggregateList) ProtoMessage() {}
func (*LocalRoutesLocRibLocalAggregatesTypeAggregateList) Descriptor() ([]byte, []int) {
	return fileDescriptor_b9ea89688009886c, []int{0, 1, 0}
}

func (m *LocalRoutesLocRibLocalAggregatesTypeAggregateList) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LocalRoutesLocRibLocalAggregatesTypeAggregateList.Unmarshal(m, b)
}
func (m *LocalRoutesLocRibLocalAggregatesTypeAggregateList) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LocalRoutesLocRibLocalAggregatesTypeAggregateList.Marshal(b, m, deterministic)
}
func (m *LocalRoutesLocRibLocalAggregatesTypeAggregateList) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LocalRoutesLocRibLocalAggregatesTypeAggregateList.Merge(m, src)
}
func (m *LocalRoutesLocRibLocalAggregatesTypeAggregateList) XXX_Size() int {
	return xxx_messageInfo_LocalRoutesLocRibLocalAggregatesTypeAggregateList.Size(m)
}
func (m *LocalRoutesLocRibLocalAggregatesTypeAggregateList) XXX_DiscardUnknown() {
	xxx_messageInfo_LocalRoutesLocRibLocalAggregatesTypeAggregateList.DiscardUnknown(m)
}

var xxx_messageInfo_LocalRoutesLocRibLocalAggregatesTypeAggregateList proto.InternalMessageInfo

func (m *LocalRoutesLocRibLocalAggregatesTypeAggregateList) GetPrefix() string {
	if m != nil && m.Prefix != nil {
		return *m.Prefix
	}
	return ""
}

func (m *LocalRoutesLocRibLocalAggregatesTypeAggregateList) GetState() *LocalRoutesLocRibLocalAggregatesTypeAggregateListStateType {
	if m != nil {
		return m.State
	}
	return nil
}

type LocalRoutesLocRibLocalAggregatesTypeAggregateListStateType struct {
	Prefix               *string  `protobuf:"bytes,51,opt,name=prefix" json:"prefix,omitempty"`
	Discard              *bool    `protobuf:"varint,52,opt,name=discard" json:"discard,omitempty"`
	SetTag               *string  `protobuf:"bytes,53,opt,name=set_tag,json=setTag" json:"set_tag,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LocalRoutesLocRibLocalAggregatesTypeAggregateListStateType) Reset() {
	*m = LocalRoutesLocRibLocalAggregatesTypeAggregateListStateType{}
}
func (m *LocalRoutesLocRibLocalAggregatesTypeAggregateListStateType) String() string {
	return proto.CompactTextString(m)
}
func (*LocalRoutesLocRibLocalAggregatesTypeAggregateListStateType) ProtoMessage() {}
func (*LocalRoutesLocRibLocalAggregatesTypeAggregateListStateType) Descriptor() ([]byte, []int) {
	return fileDescriptor_b9ea89688009886c, []int{0, 1, 0, 0}
}

func (m *LocalRoutesLocRibLocalAggregatesTypeAggregateListStateType) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LocalRoutesLocRibLocalAggregatesTypeAggregateListStateType.Unmarshal(m, b)
}
func (m *LocalRoutesLocRibLocalAggregatesTypeAggregateListStateType) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LocalRoutesLocRibLocalAggregatesTypeAggregateListStateType.Marshal(b, m, deterministic)
}
func (m *LocalRoutesLocRibLocalAggregatesTypeAggregateListStateType) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LocalRoutesLocRibLocalAggregatesTypeAggregateListStateType.Merge(m, src)
}
func (m *LocalRoutesLocRibLocalAggregatesTypeAggregateListStateType) XXX_Size() int {
	return xxx_messageInfo_LocalRoutesLocRibLocalAggregatesTypeAggregateListStateType.Size(m)
}
func (m *LocalRoutesLocRibLocalAggregatesTypeAggregateListStateType) XXX_DiscardUnknown() {
	xxx_messageInfo_LocalRoutesLocRibLocalAggregatesTypeAggregateListStateType.DiscardUnknown(m)
}

var xxx_messageInfo_LocalRoutesLocRibLocalAggregatesTypeAggregateListStateType proto.InternalMessageInfo

func (m *LocalRoutesLocRibLocalAggregatesTypeAggregateListStateType) GetPrefix() string {
	if m != nil && m.Prefix != nil {
		return *m.Prefix
	}
	return ""
}

func (m *LocalRoutesLocRibLocalAggregatesTypeAggregateListStateType) GetDiscard() bool {
	if m != nil && m.Discard != nil {
		return *m.Discard
	}
	return false
}

func (m *LocalRoutesLocRibLocalAggregatesTypeAggregateListStateType) GetSetTag() string {
	if m != nil && m.SetTag != nil {
		return *m.SetTag
	}
	return ""
}

var E_JnprLocalRoutesLocRibExt = &proto.ExtensionDesc{
	ExtendedType:  (*JuniperNetworksSensors)(nil),
	ExtensionType: (*LocalRoutesLocRib)(nil),
	Field:         66,
	Name:          "jnpr_local_routes_loc_rib_ext",
	Tag:           "bytes,66,opt,name=jnpr_local_routes_loc_rib_ext",
	Filename:      "rpd_loc_rib_oc.proto",
}

func init() {
	proto.RegisterType((*LocalRoutesLocRib)(nil), "local_routes_loc_rib")
	proto.RegisterType((*LocalRoutesLocRibStaticRoutesType)(nil), "local_routes_loc_rib.static_routes_type")
	proto.RegisterType((*LocalRoutesLocRibStaticRoutesTypeStaticList)(nil), "local_routes_loc_rib.static_routes_type.static_list")
	proto.RegisterType((*LocalRoutesLocRibStaticRoutesTypeStaticListStateType)(nil), "local_routes_loc_rib.static_routes_type.static_list.state_type")
	proto.RegisterType((*LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsType)(nil), "local_routes_loc_rib.static_routes_type.static_list.next_hops_type")
	proto.RegisterType((*LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopList)(nil), "local_routes_loc_rib.static_routes_type.static_list.next_hops_type.next_hop_list")
	proto.RegisterType((*LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListStateType)(nil), "local_routes_loc_rib.static_routes_type.static_list.next_hops_type.next_hop_list.state_type")
	proto.RegisterType((*LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefType)(nil), "local_routes_loc_rib.static_routes_type.static_list.next_hops_type.next_hop_list.interface_ref_type")
	proto.RegisterType((*LocalRoutesLocRibStaticRoutesTypeStaticListNextHopsTypeNextHopListInterfaceRefTypeStateType)(nil), "local_routes_loc_rib.static_routes_type.static_list.next_hops_type.next_hop_list.interface_ref_type.state_type")
	proto.RegisterType((*LocalRoutesLocRibLocalAggregatesType)(nil), "local_routes_loc_rib.local_aggregates_type")
	proto.RegisterType((*LocalRoutesLocRibLocalAggregatesTypeAggregateList)(nil), "local_routes_loc_rib.local_aggregates_type.aggregate_list")
	proto.RegisterType((*LocalRoutesLocRibLocalAggregatesTypeAggregateListStateType)(nil), "local_routes_loc_rib.local_aggregates_type.aggregate_list.state_type")
	proto.RegisterExtension(E_JnprLocalRoutesLocRibExt)
}

func init() { proto.RegisterFile("rpd_loc_rib_oc.proto", fileDescriptor_b9ea89688009886c) }

var fileDescriptor_b9ea89688009886c = []byte{
	// 592 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xbc, 0x55, 0xdd, 0x8a, 0xd3, 0x40,
	0x14, 0x26, 0x4a, 0xff, 0x4e, 0xb7, 0xab, 0x8c, 0x5d, 0x37, 0x06, 0x85, 0xb2, 0x57, 0x01, 0xa1,
	0x17, 0xbb, 0x5d, 0x85, 0x05, 0x11, 0x95, 0x05, 0x91, 0x52, 0x70, 0x14, 0xd7, 0x8b, 0x85, 0x21,
	0x4d, 0x4f, 0xeb, 0x68, 0xcc, 0x84, 0x99, 0x29, 0x76, 0x5f, 0x40, 0xc4, 0x17, 0xd0, 0x6b, 0xbd,
	0xf3, 0x31, 0x04, 0x9f, 0xc0, 0x07, 0xf0, 0x09, 0x7c, 0x07, 0x49, 0x26, 0x49, 0x9b, 0x36, 0x0b,
	0x6b, 0x29, 0x7b, 0xd7, 0xf3, 0xcd, 0xc9, 0x77, 0xce, 0xf9, 0xbe, 0x33, 0x53, 0x68, 0xcb, 0x68,
	0xc4, 0x02, 0xe1, 0x33, 0xc9, 0x87, 0x4c, 0xf8, 0xdd, 0x48, 0x0a, 0x2d, 0x9c, 0x1b, 0x1a, 0x03,
	0x7c, 0x8f, 0x5a, 0x9e, 0x31, 0x2d, 0x22, 0x03, 0xee, 0xfd, 0x6c, 0x41, 0x3b, 0x10, 0xbe, 0x17,
	0x30, 0x29, 0xa6, 0x1a, 0x55, 0xf6, 0x19, 0x19, 0x40, 0x4b, 0x69, 0x4f, 0x73, 0x3f, 0x3d, 0xb0,
	0xbf, 0x58, 0x1d, 0xcb, 0x6d, 0xee, 0xbb, 0xdd, 0xb2, 0xf4, 0x6e, 0x21, 0x97, 0xe9, 0xb3, 0x08,
	0xe9, 0x96, 0xc1, 0x68, 0x02, 0x91, 0x13, 0xb8, 0x6e, 0x3e, 0xf4, 0x26, 0x13, 0x89, 0x13, 0x2f,
	0xa6, 0xfc, 0x6a, 0x28, 0xef, 0x96, 0x53, 0x2e, 0xa7, 0x1b, 0xd6, 0x6b, 0x09, 0xfc, 0x28, 0x47,
	0x9d, 0x1f, 0x0d, 0x20, 0xab, 0xd5, 0x49, 0x1f, 0xaa, 0x06, 0xb5, 0x0f, 0x3a, 0x57, 0xdd, 0xe6,
	0x7e, 0xef, 0xa2, 0x7d, 0x67, 0x50, 0xc0, 0x95, 0xa6, 0x29, 0x87, 0xf3, 0xab, 0x0e, 0xcd, 0x05,
	0x9c, 0xdc, 0x84, 0x6a, 0x24, 0x71, 0xcc, 0x67, 0xf6, 0x41, 0xc7, 0x72, 0x1b, 0x34, 0x8d, 0xc8,
	0x2b, 0xa8, 0xc4, 0x69, 0x98, 0xa9, 0xf5, 0x70, 0x9d, 0xaa, 0xc9, 0x6f, 0x34, 0xe3, 0x1a, 0x3a,
	0xe2, 0x41, 0x23, 0xc4, 0x99, 0x66, 0x6f, 0x44, 0x94, 0xcb, 0xf6, 0x64, 0x2d, 0xee, 0x9c, 0xc6,
	0xf0, 0xd7, 0xe3, 0xf8, 0xa9, 0x88, 0x94, 0xf3, 0x00, 0x60, 0x5e, 0xf7, 0xdc, 0x01, 0x77, 0xa1,
	0xa6, 0x50, 0x33, 0xed, 0x4d, 0xec, 0x9e, 0x39, 0x50, 0xa8, 0x5f, 0x7a, 0x13, 0xe7, 0x7b, 0x15,
	0xb6, 0x8b, 0xdc, 0x24, 0x80, 0x7a, 0x86, 0xa4, 0x26, 0x3c, 0xdf, 0x40, 0xcb, 0x79, 0x68, 0x1c,
	0xaa, 0xa5, 0x03, 0x38, 0xdf, 0x2a, 0xd0, 0x2a, 0x1c, 0x91, 0x36, 0x54, 0x78, 0x38, 0xc2, 0x6c,
	0x04, 0x13, 0x10, 0xb5, 0x64, 0xd1, 0xe9, 0xc6, 0x7b, 0x2a, 0xf1, 0xef, 0xb3, 0x05, 0x2d, 0x1e,
	0x6a, 0x94, 0x63, 0xcf, 0x47, 0x26, 0x71, 0x9c, 0x99, 0x38, 0xda, 0x7c, 0xf5, 0x42, 0x9d, 0xf4,
	0x2a, 0xe6, 0x18, 0xc5, 0xb1, 0xf3, 0xc9, 0x2a, 0x58, 0x5d, 0x2e, 0xd3, 0xad, 0x05, 0xf3, 0x8c,
	0xd3, 0x99, 0xd2, 0xf1, 0x6e, 0xc4, 0xcf, 0x08, 0xf7, 0xed, 0xc3, 0x8e, 0xe5, 0xb6, 0x68, 0x1a,
	0x11, 0x1b, 0x6a, 0x12, 0xfd, 0xa9, 0x54, 0x68, 0xdf, 0xeb, 0x58, 0x6e, 0x9d, 0x66, 0xe1, 0xe2,
	0xd6, 0xdc, 0x2f, 0x6c, 0xcd, 0x5f, 0x0b, 0xc8, 0x6a, 0xbf, 0xe4, 0xa3, 0xb5, 0x64, 0x92, 0xb8,
	0x0c, 0x99, 0x56, 0x7d, 0x73, 0x06, 0x05, 0xa5, 0x6e, 0x43, 0x23, 0xff, 0x2a, 0x55, 0x6b, 0x0e,
	0x90, 0x3d, 0xd8, 0x52, 0xd3, 0xe1, 0x3c, 0xa1, 0x97, 0x88, 0x53, 0xc0, 0x9c, 0xdf, 0x57, 0x60,
	0xa7, 0xf4, 0x5d, 0x23, 0xaf, 0xa1, 0x91, 0x43, 0xe9, 0x6d, 0x39, 0xfa, 0x8f, 0x77, 0xb1, 0x9b,
	0xc7, 0xe6, 0x5a, 0xcc, 0xc9, 0x9c, 0x3f, 0x16, 0x6c, 0x17, 0x4f, 0xcf, 0xbd, 0xdd, 0xa7, 0x4b,
	0xb2, 0x1f, 0xaf, 0xdf, 0x41, 0x89, 0x98, 0x27, 0x17, 0x7a, 0x61, 0x6c, 0xa8, 0x8d, 0xb8, 0xf2,
	0x3d, 0x39, 0x4a, 0x14, 0xac, 0xd3, 0x2c, 0x5c, 0xdc, 0xa2, 0xc3, 0xc5, 0x2d, 0x3a, 0x12, 0x70,
	0xe7, 0x6d, 0x18, 0x49, 0x56, 0xd6, 0x2c, 0xc3, 0x99, 0x26, 0xbb, 0xdd, 0x67, 0xd3, 0x90, 0x47,
	0x28, 0x07, 0xa8, 0x3f, 0x08, 0xf9, 0x4e, 0xbd, 0xc0, 0x50, 0x09, 0xa9, 0xec, 0xc7, 0xc9, 0x98,
	0x3b, 0xa5, 0x63, 0x52, 0x3b, 0x26, 0xed, 0xc7, 0x27, 0xe6, 0x3f, 0xac, 0x2f, 0x7c, 0xca, 0x87,
	0xc7, 0x33, 0xfd, 0x2f, 0x00, 0x00, 0xff, 0xff, 0x4c, 0x5b, 0xcf, 0xca, 0x61, 0x07, 0x00, 0x00,
}