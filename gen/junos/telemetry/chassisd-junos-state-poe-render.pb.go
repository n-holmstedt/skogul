// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: chassisd-junos-state-poe-render.proto

package telemetry

import (
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
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
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type StateChassis_246 struct {
	Poe                  *StateChassis_246PoeType `protobuf:"bytes,149,opt,name=poe" json:"poe,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                 `json:"-"`
	XXX_unrecognized     []byte                   `json:"-"`
	XXX_sizecache        int32                    `json:"-"`
}

func (m *StateChassis_246) Reset()         { *m = StateChassis_246{} }
func (m *StateChassis_246) String() string { return proto.CompactTextString(m) }
func (*StateChassis_246) ProtoMessage()    {}
func (*StateChassis_246) Descriptor() ([]byte, []int) {
	return fileDescriptor_ec402508b124ba69, []int{0}
}
func (m *StateChassis_246) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_StateChassis_246.Unmarshal(m, b)
}
func (m *StateChassis_246) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_StateChassis_246.Marshal(b, m, deterministic)
}
func (m *StateChassis_246) XXX_Merge(src proto.Message) {
	xxx_messageInfo_StateChassis_246.Merge(m, src)
}
func (m *StateChassis_246) XXX_Size() int {
	return xxx_messageInfo_StateChassis_246.Size(m)
}
func (m *StateChassis_246) XXX_DiscardUnknown() {
	xxx_messageInfo_StateChassis_246.DiscardUnknown(m)
}

var xxx_messageInfo_StateChassis_246 proto.InternalMessageInfo

func (m *StateChassis_246) GetPoe() *StateChassis_246PoeType {
	if m != nil {
		return m.Poe
	}
	return nil
}

type StateChassis_246PoeType struct {
	Interfaces           *StateChassis_246PoeTypeInterfacesType  `protobuf:"bytes,150,opt,name=interfaces" json:"interfaces,omitempty"`
	Controllers          *StateChassis_246PoeTypeControllersType `protobuf:"bytes,184,opt,name=controllers" json:"controllers,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                                `json:"-"`
	XXX_unrecognized     []byte                                  `json:"-"`
	XXX_sizecache        int32                                   `json:"-"`
}

func (m *StateChassis_246PoeType) Reset()         { *m = StateChassis_246PoeType{} }
func (m *StateChassis_246PoeType) String() string { return proto.CompactTextString(m) }
func (*StateChassis_246PoeType) ProtoMessage()    {}
func (*StateChassis_246PoeType) Descriptor() ([]byte, []int) {
	return fileDescriptor_ec402508b124ba69, []int{0, 0}
}
func (m *StateChassis_246PoeType) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_StateChassis_246PoeType.Unmarshal(m, b)
}
func (m *StateChassis_246PoeType) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_StateChassis_246PoeType.Marshal(b, m, deterministic)
}
func (m *StateChassis_246PoeType) XXX_Merge(src proto.Message) {
	xxx_messageInfo_StateChassis_246PoeType.Merge(m, src)
}
func (m *StateChassis_246PoeType) XXX_Size() int {
	return xxx_messageInfo_StateChassis_246PoeType.Size(m)
}
func (m *StateChassis_246PoeType) XXX_DiscardUnknown() {
	xxx_messageInfo_StateChassis_246PoeType.DiscardUnknown(m)
}

var xxx_messageInfo_StateChassis_246PoeType proto.InternalMessageInfo

func (m *StateChassis_246PoeType) GetInterfaces() *StateChassis_246PoeTypeInterfacesType {
	if m != nil {
		return m.Interfaces
	}
	return nil
}

func (m *StateChassis_246PoeType) GetControllers() *StateChassis_246PoeTypeControllersType {
	if m != nil {
		return m.Controllers
	}
	return nil
}

type StateChassis_246PoeTypeInterfacesType struct {
	Interface            []*StateChassis_246PoeTypeInterfacesTypeInterfaceList `protobuf:"bytes,151,rep,name=interface" json:"interface,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                                              `json:"-"`
	XXX_unrecognized     []byte                                                `json:"-"`
	XXX_sizecache        int32                                                 `json:"-"`
}

func (m *StateChassis_246PoeTypeInterfacesType) Reset()         { *m = StateChassis_246PoeTypeInterfacesType{} }
func (m *StateChassis_246PoeTypeInterfacesType) String() string { return proto.CompactTextString(m) }
func (*StateChassis_246PoeTypeInterfacesType) ProtoMessage()    {}
func (*StateChassis_246PoeTypeInterfacesType) Descriptor() ([]byte, []int) {
	return fileDescriptor_ec402508b124ba69, []int{0, 0, 0}
}
func (m *StateChassis_246PoeTypeInterfacesType) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_StateChassis_246PoeTypeInterfacesType.Unmarshal(m, b)
}
func (m *StateChassis_246PoeTypeInterfacesType) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_StateChassis_246PoeTypeInterfacesType.Marshal(b, m, deterministic)
}
func (m *StateChassis_246PoeTypeInterfacesType) XXX_Merge(src proto.Message) {
	xxx_messageInfo_StateChassis_246PoeTypeInterfacesType.Merge(m, src)
}
func (m *StateChassis_246PoeTypeInterfacesType) XXX_Size() int {
	return xxx_messageInfo_StateChassis_246PoeTypeInterfacesType.Size(m)
}
func (m *StateChassis_246PoeTypeInterfacesType) XXX_DiscardUnknown() {
	xxx_messageInfo_StateChassis_246PoeTypeInterfacesType.DiscardUnknown(m)
}

var xxx_messageInfo_StateChassis_246PoeTypeInterfacesType proto.InternalMessageInfo

func (m *StateChassis_246PoeTypeInterfacesType) GetInterface() []*StateChassis_246PoeTypeInterfacesTypeInterfaceList {
	if m != nil {
		return m.Interface
	}
	return nil
}

type StateChassis_246PoeTypeInterfacesTypeInterfaceList struct {
	Name                     *string  `protobuf:"bytes,152,opt,name=name" json:"name,omitempty"`
	AdminStatus              *string  `protobuf:"bytes,153,opt,name=admin_status,json=adminStatus" json:"admin_status,omitempty"`
	OperStatus               *string  `protobuf:"bytes,154,opt,name=oper_status,json=operStatus" json:"oper_status,omitempty"`
	PoeFourPair              *string  `protobuf:"bytes,156,opt,name=poe_four_pair,json=poeFourPair" json:"poe_four_pair,omitempty"`
	PoePairStatus            *string  `protobuf:"bytes,157,opt,name=poe_pair_status,json=poePairStatus" json:"poe_pair_status,omitempty"`
	PowerLimit               *float64 `protobuf:"fixed64,158,opt,name=power_limit,json=powerLimit" json:"power_limit,omitempty"`
	PowerLimitLldpNegotiated *bool    `protobuf:"varint,159,opt,name=power_limit_lldp_negotiated,json=powerLimitLldpNegotiated" json:"power_limit_lldp_negotiated,omitempty"`
	Priority                 *string  `protobuf:"bytes,160,opt,name=priority" json:"priority,omitempty"`
	PriorityLldpNegotiated   *bool    `protobuf:"varint,161,opt,name=priority_lldp_negotiated,json=priorityLldpNegotiated" json:"priority_lldp_negotiated,omitempty"`
	PowerConsumption         *float64 `protobuf:"fixed64,162,opt,name=power_consumption,json=powerConsumption" json:"power_consumption,omitempty"`
	PowerOverConsumed        *bool    `protobuf:"varint,163,opt,name=power_over_consumed,json=powerOverConsumed" json:"power_over_consumed,omitempty"`
	PowerClassA              *string  `protobuf:"bytes,164,opt,name=power_class_a,json=powerClassA" json:"power_class_a,omitempty"`
	PowerClassB              *string  `protobuf:"bytes,165,opt,name=power_class_b,json=powerClassB" json:"power_class_b,omitempty"`
	PoeMode                  *string  `protobuf:"bytes,166,opt,name=poe_mode,json=poeMode" json:"poe_mode,omitempty"`
	XXX_NoUnkeyedLiteral     struct{} `json:"-"`
	XXX_unrecognized         []byte   `json:"-"`
	XXX_sizecache            int32    `json:"-"`
}

func (m *StateChassis_246PoeTypeInterfacesTypeInterfaceList) Reset() {
	*m = StateChassis_246PoeTypeInterfacesTypeInterfaceList{}
}
func (m *StateChassis_246PoeTypeInterfacesTypeInterfaceList) String() string {
	return proto.CompactTextString(m)
}
func (*StateChassis_246PoeTypeInterfacesTypeInterfaceList) ProtoMessage() {}
func (*StateChassis_246PoeTypeInterfacesTypeInterfaceList) Descriptor() ([]byte, []int) {
	return fileDescriptor_ec402508b124ba69, []int{0, 0, 0, 0}
}
func (m *StateChassis_246PoeTypeInterfacesTypeInterfaceList) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_StateChassis_246PoeTypeInterfacesTypeInterfaceList.Unmarshal(m, b)
}
func (m *StateChassis_246PoeTypeInterfacesTypeInterfaceList) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_StateChassis_246PoeTypeInterfacesTypeInterfaceList.Marshal(b, m, deterministic)
}
func (m *StateChassis_246PoeTypeInterfacesTypeInterfaceList) XXX_Merge(src proto.Message) {
	xxx_messageInfo_StateChassis_246PoeTypeInterfacesTypeInterfaceList.Merge(m, src)
}
func (m *StateChassis_246PoeTypeInterfacesTypeInterfaceList) XXX_Size() int {
	return xxx_messageInfo_StateChassis_246PoeTypeInterfacesTypeInterfaceList.Size(m)
}
func (m *StateChassis_246PoeTypeInterfacesTypeInterfaceList) XXX_DiscardUnknown() {
	xxx_messageInfo_StateChassis_246PoeTypeInterfacesTypeInterfaceList.DiscardUnknown(m)
}

var xxx_messageInfo_StateChassis_246PoeTypeInterfacesTypeInterfaceList proto.InternalMessageInfo

func (m *StateChassis_246PoeTypeInterfacesTypeInterfaceList) GetName() string {
	if m != nil && m.Name != nil {
		return *m.Name
	}
	return ""
}

func (m *StateChassis_246PoeTypeInterfacesTypeInterfaceList) GetAdminStatus() string {
	if m != nil && m.AdminStatus != nil {
		return *m.AdminStatus
	}
	return ""
}

func (m *StateChassis_246PoeTypeInterfacesTypeInterfaceList) GetOperStatus() string {
	if m != nil && m.OperStatus != nil {
		return *m.OperStatus
	}
	return ""
}

func (m *StateChassis_246PoeTypeInterfacesTypeInterfaceList) GetPoeFourPair() string {
	if m != nil && m.PoeFourPair != nil {
		return *m.PoeFourPair
	}
	return ""
}

func (m *StateChassis_246PoeTypeInterfacesTypeInterfaceList) GetPoePairStatus() string {
	if m != nil && m.PoePairStatus != nil {
		return *m.PoePairStatus
	}
	return ""
}

func (m *StateChassis_246PoeTypeInterfacesTypeInterfaceList) GetPowerLimit() float64 {
	if m != nil && m.PowerLimit != nil {
		return *m.PowerLimit
	}
	return 0
}

func (m *StateChassis_246PoeTypeInterfacesTypeInterfaceList) GetPowerLimitLldpNegotiated() bool {
	if m != nil && m.PowerLimitLldpNegotiated != nil {
		return *m.PowerLimitLldpNegotiated
	}
	return false
}

func (m *StateChassis_246PoeTypeInterfacesTypeInterfaceList) GetPriority() string {
	if m != nil && m.Priority != nil {
		return *m.Priority
	}
	return ""
}

func (m *StateChassis_246PoeTypeInterfacesTypeInterfaceList) GetPriorityLldpNegotiated() bool {
	if m != nil && m.PriorityLldpNegotiated != nil {
		return *m.PriorityLldpNegotiated
	}
	return false
}

func (m *StateChassis_246PoeTypeInterfacesTypeInterfaceList) GetPowerConsumption() float64 {
	if m != nil && m.PowerConsumption != nil {
		return *m.PowerConsumption
	}
	return 0
}

func (m *StateChassis_246PoeTypeInterfacesTypeInterfaceList) GetPowerOverConsumed() bool {
	if m != nil && m.PowerOverConsumed != nil {
		return *m.PowerOverConsumed
	}
	return false
}

func (m *StateChassis_246PoeTypeInterfacesTypeInterfaceList) GetPowerClassA() string {
	if m != nil && m.PowerClassA != nil {
		return *m.PowerClassA
	}
	return ""
}

func (m *StateChassis_246PoeTypeInterfacesTypeInterfaceList) GetPowerClassB() string {
	if m != nil && m.PowerClassB != nil {
		return *m.PowerClassB
	}
	return ""
}

func (m *StateChassis_246PoeTypeInterfacesTypeInterfaceList) GetPoeMode() string {
	if m != nil && m.PoeMode != nil {
		return *m.PoeMode
	}
	return ""
}

type StateChassis_246PoeTypeControllersType struct {
	FastPoeEnabled       *bool                                                   `protobuf:"varint,183,opt,name=fast_poe_enabled,json=fastPoeEnabled" json:"fast_poe_enabled,omitempty"`
	PerpetualPoeEnabled  *bool                                                   `protobuf:"varint,184,opt,name=perpetual_poe_enabled,json=perpetualPoeEnabled" json:"perpetual_poe_enabled,omitempty"`
	Controller           []*StateChassis_246PoeTypeControllersTypeControllerList `protobuf:"bytes,185,rep,name=controller" json:"controller,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                                                `json:"-"`
	XXX_unrecognized     []byte                                                  `json:"-"`
	XXX_sizecache        int32                                                   `json:"-"`
}

func (m *StateChassis_246PoeTypeControllersType) Reset() {
	*m = StateChassis_246PoeTypeControllersType{}
}
func (m *StateChassis_246PoeTypeControllersType) String() string { return proto.CompactTextString(m) }
func (*StateChassis_246PoeTypeControllersType) ProtoMessage()    {}
func (*StateChassis_246PoeTypeControllersType) Descriptor() ([]byte, []int) {
	return fileDescriptor_ec402508b124ba69, []int{0, 0, 1}
}
func (m *StateChassis_246PoeTypeControllersType) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_StateChassis_246PoeTypeControllersType.Unmarshal(m, b)
}
func (m *StateChassis_246PoeTypeControllersType) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_StateChassis_246PoeTypeControllersType.Marshal(b, m, deterministic)
}
func (m *StateChassis_246PoeTypeControllersType) XXX_Merge(src proto.Message) {
	xxx_messageInfo_StateChassis_246PoeTypeControllersType.Merge(m, src)
}
func (m *StateChassis_246PoeTypeControllersType) XXX_Size() int {
	return xxx_messageInfo_StateChassis_246PoeTypeControllersType.Size(m)
}
func (m *StateChassis_246PoeTypeControllersType) XXX_DiscardUnknown() {
	xxx_messageInfo_StateChassis_246PoeTypeControllersType.DiscardUnknown(m)
}

var xxx_messageInfo_StateChassis_246PoeTypeControllersType proto.InternalMessageInfo

func (m *StateChassis_246PoeTypeControllersType) GetFastPoeEnabled() bool {
	if m != nil && m.FastPoeEnabled != nil {
		return *m.FastPoeEnabled
	}
	return false
}

func (m *StateChassis_246PoeTypeControllersType) GetPerpetualPoeEnabled() bool {
	if m != nil && m.PerpetualPoeEnabled != nil {
		return *m.PerpetualPoeEnabled
	}
	return false
}

func (m *StateChassis_246PoeTypeControllersType) GetController() []*StateChassis_246PoeTypeControllersTypeControllerList {
	if m != nil {
		return m.Controller
	}
	return nil
}

type StateChassis_246PoeTypeControllersTypeControllerList struct {
	Index                *uint32  `protobuf:"varint,186,opt,name=index" json:"index,omitempty"`
	FirmwareAvailable    *bool    `protobuf:"varint,187,opt,name=firmware_available,json=firmwareAvailable" json:"firmware_available,omitempty"`
	MaxPower             *float64 `protobuf:"fixed64,188,opt,name=max_power,json=maxPower" json:"max_power,omitempty"`
	PowerConsumption     *float64 `protobuf:"fixed64,189,opt,name=power_consumption,json=powerConsumption" json:"power_consumption,omitempty"`
	PowerOverConsumed    *bool    `protobuf:"varint,190,opt,name=power_over_consumed,json=powerOverConsumed" json:"power_over_consumed,omitempty"`
	GuardBand            *uint64  `protobuf:"varint,191,opt,name=guard_band,json=guardBand" json:"guard_band,omitempty"`
	PoeManagement        *string  `protobuf:"bytes,192,opt,name=poe_management,json=poeManagement" json:"poe_management,omitempty"`
	PoeStatus            *string  `protobuf:"bytes,193,opt,name=poe_status,json=poeStatus" json:"poe_status,omitempty"`
	LldpPriority         *string  `protobuf:"bytes,194,opt,name=lldp_priority,json=lldpPriority" json:"lldp_priority,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *StateChassis_246PoeTypeControllersTypeControllerList) Reset() {
	*m = StateChassis_246PoeTypeControllersTypeControllerList{}
}
func (m *StateChassis_246PoeTypeControllersTypeControllerList) String() string {
	return proto.CompactTextString(m)
}
func (*StateChassis_246PoeTypeControllersTypeControllerList) ProtoMessage() {}
func (*StateChassis_246PoeTypeControllersTypeControllerList) Descriptor() ([]byte, []int) {
	return fileDescriptor_ec402508b124ba69, []int{0, 0, 1, 0}
}
func (m *StateChassis_246PoeTypeControllersTypeControllerList) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_StateChassis_246PoeTypeControllersTypeControllerList.Unmarshal(m, b)
}
func (m *StateChassis_246PoeTypeControllersTypeControllerList) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_StateChassis_246PoeTypeControllersTypeControllerList.Marshal(b, m, deterministic)
}
func (m *StateChassis_246PoeTypeControllersTypeControllerList) XXX_Merge(src proto.Message) {
	xxx_messageInfo_StateChassis_246PoeTypeControllersTypeControllerList.Merge(m, src)
}
func (m *StateChassis_246PoeTypeControllersTypeControllerList) XXX_Size() int {
	return xxx_messageInfo_StateChassis_246PoeTypeControllersTypeControllerList.Size(m)
}
func (m *StateChassis_246PoeTypeControllersTypeControllerList) XXX_DiscardUnknown() {
	xxx_messageInfo_StateChassis_246PoeTypeControllersTypeControllerList.DiscardUnknown(m)
}

var xxx_messageInfo_StateChassis_246PoeTypeControllersTypeControllerList proto.InternalMessageInfo

func (m *StateChassis_246PoeTypeControllersTypeControllerList) GetIndex() uint32 {
	if m != nil && m.Index != nil {
		return *m.Index
	}
	return 0
}

func (m *StateChassis_246PoeTypeControllersTypeControllerList) GetFirmwareAvailable() bool {
	if m != nil && m.FirmwareAvailable != nil {
		return *m.FirmwareAvailable
	}
	return false
}

func (m *StateChassis_246PoeTypeControllersTypeControllerList) GetMaxPower() float64 {
	if m != nil && m.MaxPower != nil {
		return *m.MaxPower
	}
	return 0
}

func (m *StateChassis_246PoeTypeControllersTypeControllerList) GetPowerConsumption() float64 {
	if m != nil && m.PowerConsumption != nil {
		return *m.PowerConsumption
	}
	return 0
}

func (m *StateChassis_246PoeTypeControllersTypeControllerList) GetPowerOverConsumed() bool {
	if m != nil && m.PowerOverConsumed != nil {
		return *m.PowerOverConsumed
	}
	return false
}

func (m *StateChassis_246PoeTypeControllersTypeControllerList) GetGuardBand() uint64 {
	if m != nil && m.GuardBand != nil {
		return *m.GuardBand
	}
	return 0
}

func (m *StateChassis_246PoeTypeControllersTypeControllerList) GetPoeManagement() string {
	if m != nil && m.PoeManagement != nil {
		return *m.PoeManagement
	}
	return ""
}

func (m *StateChassis_246PoeTypeControllersTypeControllerList) GetPoeStatus() string {
	if m != nil && m.PoeStatus != nil {
		return *m.PoeStatus
	}
	return ""
}

func (m *StateChassis_246PoeTypeControllersTypeControllerList) GetLldpPriority() string {
	if m != nil && m.LldpPriority != nil {
		return *m.LldpPriority
	}
	return ""
}

var E_JnprStateChassis_246Ext = &proto.ExtensionDesc{
	ExtendedType:  (*JuniperNetworksSensors)(nil),
	ExtensionType: (*StateChassis_246)(nil),
	Field:         246,
	Name:          "jnpr_state_chassis_246_ext",
	Tag:           "bytes,246,opt,name=jnpr_state_chassis_246_ext",
	Filename:      "chassisd-junos-state-poe-render.proto",
}

func init() {
	proto.RegisterType((*StateChassis_246)(nil), "state_chassis_246")
	proto.RegisterType((*StateChassis_246PoeType)(nil), "state_chassis_246.poe_type")
	proto.RegisterType((*StateChassis_246PoeTypeInterfacesType)(nil), "state_chassis_246.poe_type.interfaces_type")
	proto.RegisterType((*StateChassis_246PoeTypeInterfacesTypeInterfaceList)(nil), "state_chassis_246.poe_type.interfaces_type.interface_list")
	proto.RegisterType((*StateChassis_246PoeTypeControllersType)(nil), "state_chassis_246.poe_type.controllers_type")
	proto.RegisterType((*StateChassis_246PoeTypeControllersTypeControllerList)(nil), "state_chassis_246.poe_type.controllers_type.controller_list")
	proto.RegisterExtension(E_JnprStateChassis_246Ext)
}

func init() {
	proto.RegisterFile("chassisd-junos-state-poe-render.proto", fileDescriptor_ec402508b124ba69)
}

var fileDescriptor_ec402508b124ba69 = []byte{
	// 775 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x94, 0xcb, 0x6e, 0x1b, 0x37,
	0x14, 0x86, 0xa1, 0x44, 0x46, 0xa5, 0xa3, 0xf8, 0x12, 0x1a, 0x4d, 0x89, 0x71, 0x50, 0x18, 0xe9,
	0x2d, 0x45, 0x23, 0x15, 0x50, 0x83, 0x00, 0x0d, 0x8a, 0xa2, 0x71, 0x90, 0x2e, 0x0a, 0x27, 0x16,
	0xc6, 0xab, 0x2e, 0x0a, 0x82, 0xd6, 0x1c, 0xd9, 0x74, 0x67, 0x48, 0x82, 0xe4, 0xd8, 0xf2, 0xb6,
	0xef, 0xd0, 0xfb, 0xfd, 0xba, 0xec, 0xb6, 0xee, 0xcd, 0x6e, 0xfb, 0x26, 0xdd, 0xf6, 0x01, 0xba,
	0x2e, 0x38, 0xd4, 0xcc, 0xc8, 0x52, 0x63, 0xc0, 0x3b, 0xe9, 0x3f, 0xdf, 0xf9, 0x79, 0xc4, 0xc3,
	0x5f, 0xf0, 0xdc, 0x70, 0x8f, 0x5b, 0x2b, 0x6c, 0xd2, 0xdd, 0xcf, 0xa5, 0xb2, 0x5d, 0xeb, 0xb8,
	0xc3, 0xae, 0x56, 0xd8, 0x35, 0x28, 0x13, 0x34, 0x3d, 0x6d, 0x94, 0x53, 0xd1, 0xaa, 0xc3, 0x14,
	0x33, 0x74, 0xe6, 0x88, 0x39, 0xa5, 0x83, 0x78, 0xe3, 0xef, 0x0e, 0x5c, 0x2d, 0x78, 0x36, 0x31,
	0x61, 0xfd, 0xdb, 0x77, 0x48, 0x0f, 0x2e, 0x6b, 0x85, 0xf4, 0xfd, 0xc6, 0x7a, 0xe3, 0x66, 0xa7,
	0xbf, 0xd6, 0x9b, 0x23, 0x7a, 0x5a, 0x21, 0x73, 0x47, 0x1a, 0x63, 0x0f, 0x46, 0x9f, 0x76, 0xa0,
	0x55, 0x2a, 0x64, 0x13, 0x40, 0x48, 0x87, 0x66, 0xc4, 0x87, 0x68, 0xe9, 0x07, 0xc1, 0xe3, 0xa5,
	0x73, 0x3c, 0x7a, 0x35, 0x1e, 0x3c, 0xa7, 0xfa, 0xc9, 0x16, 0x74, 0x86, 0x4a, 0x3a, 0xa3, 0xd2,
	0x14, 0x8d, 0xa5, 0xc7, 0xc1, 0xee, 0xd6, 0x79, 0x76, 0x53, 0x7c, 0xf0, 0x9b, 0x76, 0x88, 0x7e,
	0x5c, 0x80, 0xe5, 0x99, 0x03, 0xc9, 0xdb, 0xd0, 0xae, 0x24, 0xfa, 0x61, 0x63, 0xfd, 0xf2, 0xcd,
	0x4e, 0xff, 0xee, 0x05, 0x26, 0xae, 0xbf, 0xb3, 0x54, 0x58, 0x17, 0xd7, 0x6e, 0xd1, 0x69, 0x13,
	0x96, 0xce, 0x56, 0x49, 0x04, 0x4d, 0xc9, 0x33, 0xa4, 0x1f, 0xf9, 0xdf, 0xd2, 0xde, 0x58, 0x78,
	0xef, 0x8d, 0x4b, 0xad, 0x46, 0x5c, 0x68, 0xe4, 0x06, 0x5c, 0xe1, 0x49, 0x26, 0x24, 0xf3, 0x87,
	0xe7, 0x96, 0x7e, 0x5c, 0x30, 0x71, 0xa7, 0x10, 0xb7, 0x0b, 0x8d, 0xac, 0x43, 0x47, 0x69, 0x34,
	0x25, 0xf2, 0x49, 0x40, 0xc0, 0x6b, 0x13, 0xe2, 0x19, 0x58, 0xf4, 0xa3, 0x8e, 0x54, 0x6e, 0x98,
	0xe6, 0xc2, 0xd0, 0xcf, 0x26, 0x36, 0x5a, 0xe1, 0x9b, 0x2a, 0x37, 0x03, 0x2e, 0x0c, 0x79, 0x01,
	0x96, 0x3d, 0xe4, 0xeb, 0xa5, 0xd5, 0xe7, 0x01, 0xf3, 0xcd, 0x1e, 0xa9, 0xcf, 0xd3, 0xea, 0x10,
	0x0d, 0x4b, 0x45, 0x26, 0x1c, 0xfd, 0xc2, 0x43, 0x8d, 0x18, 0x0a, 0x6d, 0xd3, 0x4b, 0xe4, 0x75,
	0x58, 0x9b, 0x22, 0x58, 0x9a, 0x26, 0x9a, 0x49, 0xdc, 0x55, 0x4e, 0x70, 0x87, 0x09, 0xfd, 0xd2,
	0x77, 0xb4, 0x62, 0x5a, 0x77, 0x6c, 0xa6, 0x89, 0x7e, 0x54, 0x01, 0x64, 0x0d, 0x5a, 0xda, 0x08,
	0x65, 0x84, 0x3b, 0xa2, 0x5f, 0x85, 0x19, 0x2a, 0x81, 0xbc, 0x0a, 0xb4, 0xfc, 0x3c, 0xe7, 0xfc,
	0x75, 0x70, 0xbe, 0x56, 0x02, 0x33, 0xbe, 0xb7, 0xe0, 0x6a, 0x98, 0x6b, 0xa8, 0xa4, 0xcd, 0x33,
	0xed, 0x84, 0x92, 0xf4, 0x9b, 0x30, 0xff, 0x4a, 0x51, 0xb9, 0x5f, 0x17, 0xc8, 0xcb, 0xb0, 0x1a,
	0x68, 0x75, 0x50, 0xb5, 0x60, 0x42, 0xbf, 0x0d, 0x67, 0x04, 0xa7, 0xad, 0x83, 0xb2, 0x07, 0x93,
	0x70, 0xcd, 0x85, 0x7d, 0xca, 0xad, 0x65, 0x9c, 0x7e, 0x57, 0x5d, 0xb3, 0xb7, 0xf6, 0xe2, 0xbd,
	0x59, 0x68, 0x87, 0x7e, 0x3f, 0x07, 0x6d, 0x90, 0x28, 0xe4, 0x27, 0x53, 0x09, 0xd2, 0x1f, 0x42,
	0xfd, 0x09, 0xad, 0xf0, 0xa1, 0x4a, 0x30, 0x3a, 0x69, 0xc2, 0xca, 0xec, 0x93, 0x26, 0x2f, 0xc2,
	0xca, 0x88, 0x5b, 0xc7, 0x7c, 0x17, 0x4a, 0xbe, 0x93, 0x62, 0x42, 0x7f, 0x0a, 0x83, 0x2e, 0xf9,
	0xc2, 0x40, 0xe1, 0x83, 0x20, 0x93, 0x57, 0xe0, 0x49, 0x8d, 0x46, 0xa3, 0xcb, 0x79, 0x7a, 0x86,
	0x3f, 0x0e, 0xfc, 0x6a, 0x55, 0x9d, 0x6a, 0x7a, 0x07, 0xa0, 0x3e, 0x93, 0xfe, 0x1c, 0x22, 0xf1,
	0xda, 0x45, 0x52, 0x37, 0x25, 0x84, 0x50, 0x4c, 0x19, 0x46, 0xff, 0x5c, 0x82, 0xe5, 0x99, 0x3a,
	0xb9, 0x0e, 0x0b, 0x42, 0x26, 0x38, 0xa6, 0xbf, 0xf8, 0xb9, 0x16, 0xcb, 0x5c, 0x04, 0x91, 0xf4,
	0x80, 0x8c, 0x84, 0xc9, 0x0e, 0xb9, 0x41, 0xc6, 0x0f, 0xb8, 0x48, 0xfd, 0x9c, 0xf4, 0xd7, 0xc9,
	0x6e, 0xca, 0xd2, 0xbd, 0xb2, 0x42, 0xae, 0x43, 0x3b, 0xe3, 0x63, 0x56, 0x5c, 0x32, 0xfd, 0x2d,
	0xac, 0xbc, 0x95, 0xf1, 0xf1, 0xc0, 0x0b, 0xff, 0xff, 0x30, 0x7e, 0xbf, 0xe0, 0xc3, 0x38, 0x79,
	0xec, 0xc3, 0x78, 0x1a, 0x60, 0x37, 0xe7, 0x26, 0x61, 0x3b, 0x5c, 0x26, 0xf4, 0xd4, 0x73, 0xcd,
	0xb8, 0x5d, 0x48, 0x1b, 0x5c, 0x26, 0xe4, 0x79, 0x58, 0x2a, 0xd6, 0xcd, 0x25, 0xdf, 0xc5, 0x0c,
	0xa5, 0xa3, 0x7f, 0xd4, 0xc9, 0x7b, 0x58, 0xa9, 0xde, 0xc7, 0x73, 0x93, 0x74, 0xfe, 0x19, 0x98,
	0xb6, 0x56, 0x38, 0x49, 0xe6, 0xb3, 0xb0, 0x58, 0x24, 0xa2, 0x0a, 0xcf, 0x5f, 0x01, 0xb9, 0xe2,
	0xd5, 0xc1, 0x44, 0xbc, 0xbb, 0x07, 0xd1, 0xbe, 0xd4, 0x21, 0xe4, 0x67, 0x96, 0xc7, 0x70, 0xec,
	0xc8, 0x53, 0xbd, 0xb7, 0x72, 0x29, 0x34, 0x9a, 0x47, 0xe8, 0x0e, 0x95, 0x79, 0xd7, 0x6e, 0xa3,
	0xb4, 0xca, 0x58, 0xfa, 0x6f, 0xf8, 0xab, 0x25, 0xf3, 0x4b, 0x8f, 0xaf, 0x79, 0x3f, 0x3f, 0x03,
	0xde, 0x0f, 0x6a, 0xff, 0xf6, 0x9d, 0x07, 0x63, 0xf7, 0x5f, 0x00, 0x00, 0x00, 0xff, 0xff, 0x5d,
	0xa4, 0x54, 0x5c, 0x8a, 0x06, 0x00, 0x00,
}