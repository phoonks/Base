// Copyright (c) 2020 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

// To compile the proto, run:
//      protoc --go_out=plugins=grpc:$GOPATH/src *.proto

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        v5.27.1
// source: proto/types/state_data.proto

package iotextypes

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// ProbationCandidateList (slashing #1)
type ProbationCandidateList struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ProbationList []*ProbationCandidateList_Info `protobuf:"bytes,1,rep,name=probationList,proto3" json:"probationList,omitempty"`
	IntensityRate uint32                         `protobuf:"varint,2,opt,name=intensityRate,proto3" json:"intensityRate,omitempty"`
}

func (x *ProbationCandidateList) Reset() {
	*x = ProbationCandidateList{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_types_state_data_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ProbationCandidateList) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProbationCandidateList) ProtoMessage() {}

func (x *ProbationCandidateList) ProtoReflect() protoreflect.Message {
	mi := &file_proto_types_state_data_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProbationCandidateList.ProtoReflect.Descriptor instead.
func (*ProbationCandidateList) Descriptor() ([]byte, []int) {
	return file_proto_types_state_data_proto_rawDescGZIP(), []int{0}
}

func (x *ProbationCandidateList) GetProbationList() []*ProbationCandidateList_Info {
	if x != nil {
		return x.ProbationList
	}
	return nil
}

func (x *ProbationCandidateList) GetIntensityRate() uint32 {
	if x != nil {
		return x.IntensityRate
	}
	return 0
}

type VoteBucket struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Index                        uint64                 `protobuf:"varint,1,opt,name=index,proto3" json:"index,omitempty"`
	CandidateAddress             string                 `protobuf:"bytes,2,opt,name=candidateAddress,proto3" json:"candidateAddress,omitempty"`
	StakedAmount                 string                 `protobuf:"bytes,3,opt,name=stakedAmount,proto3" json:"stakedAmount,omitempty"`
	StakedDuration               uint32                 `protobuf:"varint,4,opt,name=stakedDuration,proto3" json:"stakedDuration,omitempty"`
	CreateTime                   *timestamppb.Timestamp `protobuf:"bytes,5,opt,name=createTime,proto3" json:"createTime,omitempty"`
	StakeStartTime               *timestamppb.Timestamp `protobuf:"bytes,6,opt,name=stakeStartTime,proto3" json:"stakeStartTime,omitempty"`
	UnstakeStartTime             *timestamppb.Timestamp `protobuf:"bytes,7,opt,name=unstakeStartTime,proto3" json:"unstakeStartTime,omitempty"`
	AutoStake                    bool                   `protobuf:"varint,8,opt,name=autoStake,proto3" json:"autoStake,omitempty"`
	Owner                        string                 `protobuf:"bytes,9,opt,name=owner,proto3" json:"owner,omitempty"`
	ContractAddress              string                 `protobuf:"bytes,10,opt,name=contractAddress,proto3" json:"contractAddress,omitempty"`
	StakedDurationBlockNumber    uint64                 `protobuf:"varint,11,opt,name=stakedDurationBlockNumber,proto3" json:"stakedDurationBlockNumber,omitempty"`
	CreateBlockHeight            uint64                 `protobuf:"varint,12,opt,name=createBlockHeight,proto3" json:"createBlockHeight,omitempty"`
	StakeStartBlockHeight        uint64                 `protobuf:"varint,13,opt,name=stakeStartBlockHeight,proto3" json:"stakeStartBlockHeight,omitempty"`
	UnstakeStartBlockHeight      uint64                 `protobuf:"varint,14,opt,name=unstakeStartBlockHeight,proto3" json:"unstakeStartBlockHeight,omitempty"`
	EndorsementExpireBlockHeight uint64                 `protobuf:"varint,15,opt,name=endorsementExpireBlockHeight,proto3" json:"endorsementExpireBlockHeight,omitempty"`
}

func (x *VoteBucket) Reset() {
	*x = VoteBucket{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_types_state_data_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *VoteBucket) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VoteBucket) ProtoMessage() {}

func (x *VoteBucket) ProtoReflect() protoreflect.Message {
	mi := &file_proto_types_state_data_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VoteBucket.ProtoReflect.Descriptor instead.
func (*VoteBucket) Descriptor() ([]byte, []int) {
	return file_proto_types_state_data_proto_rawDescGZIP(), []int{1}
}

func (x *VoteBucket) GetIndex() uint64 {
	if x != nil {
		return x.Index
	}
	return 0
}

func (x *VoteBucket) GetCandidateAddress() string {
	if x != nil {
		return x.CandidateAddress
	}
	return ""
}

func (x *VoteBucket) GetStakedAmount() string {
	if x != nil {
		return x.StakedAmount
	}
	return ""
}

func (x *VoteBucket) GetStakedDuration() uint32 {
	if x != nil {
		return x.StakedDuration
	}
	return 0
}

func (x *VoteBucket) GetCreateTime() *timestamppb.Timestamp {
	if x != nil {
		return x.CreateTime
	}
	return nil
}

func (x *VoteBucket) GetStakeStartTime() *timestamppb.Timestamp {
	if x != nil {
		return x.StakeStartTime
	}
	return nil
}

func (x *VoteBucket) GetUnstakeStartTime() *timestamppb.Timestamp {
	if x != nil {
		return x.UnstakeStartTime
	}
	return nil
}

func (x *VoteBucket) GetAutoStake() bool {
	if x != nil {
		return x.AutoStake
	}
	return false
}

func (x *VoteBucket) GetOwner() string {
	if x != nil {
		return x.Owner
	}
	return ""
}

func (x *VoteBucket) GetContractAddress() string {
	if x != nil {
		return x.ContractAddress
	}
	return ""
}

func (x *VoteBucket) GetStakedDurationBlockNumber() uint64 {
	if x != nil {
		return x.StakedDurationBlockNumber
	}
	return 0
}

func (x *VoteBucket) GetCreateBlockHeight() uint64 {
	if x != nil {
		return x.CreateBlockHeight
	}
	return 0
}

func (x *VoteBucket) GetStakeStartBlockHeight() uint64 {
	if x != nil {
		return x.StakeStartBlockHeight
	}
	return 0
}

func (x *VoteBucket) GetUnstakeStartBlockHeight() uint64 {
	if x != nil {
		return x.UnstakeStartBlockHeight
	}
	return 0
}

func (x *VoteBucket) GetEndorsementExpireBlockHeight() uint64 {
	if x != nil {
		return x.EndorsementExpireBlockHeight
	}
	return 0
}

type VoteBucketList struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Buckets []*VoteBucket `protobuf:"bytes,1,rep,name=buckets,proto3" json:"buckets,omitempty"`
}

func (x *VoteBucketList) Reset() {
	*x = VoteBucketList{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_types_state_data_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *VoteBucketList) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*VoteBucketList) ProtoMessage() {}

func (x *VoteBucketList) ProtoReflect() protoreflect.Message {
	mi := &file_proto_types_state_data_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use VoteBucketList.ProtoReflect.Descriptor instead.
func (*VoteBucketList) Descriptor() ([]byte, []int) {
	return file_proto_types_state_data_proto_rawDescGZIP(), []int{2}
}

func (x *VoteBucketList) GetBuckets() []*VoteBucket {
	if x != nil {
		return x.Buckets
	}
	return nil
}

type CandidateV2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	OwnerAddress       string `protobuf:"bytes,1,opt,name=ownerAddress,proto3" json:"ownerAddress,omitempty"`
	OperatorAddress    string `protobuf:"bytes,2,opt,name=operatorAddress,proto3" json:"operatorAddress,omitempty"`
	RewardAddress      string `protobuf:"bytes,3,opt,name=rewardAddress,proto3" json:"rewardAddress,omitempty"`
	Name               string `protobuf:"bytes,4,opt,name=name,proto3" json:"name,omitempty"`
	TotalWeightedVotes string `protobuf:"bytes,5,opt,name=totalWeightedVotes,proto3" json:"totalWeightedVotes,omitempty"`
	SelfStakeBucketIdx uint64 `protobuf:"varint,6,opt,name=selfStakeBucketIdx,proto3" json:"selfStakeBucketIdx,omitempty"`
	SelfStakingTokens  string `protobuf:"bytes,7,opt,name=selfStakingTokens,proto3" json:"selfStakingTokens,omitempty"`
	Id                 string `protobuf:"bytes,8,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *CandidateV2) Reset() {
	*x = CandidateV2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_types_state_data_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CandidateV2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CandidateV2) ProtoMessage() {}

func (x *CandidateV2) ProtoReflect() protoreflect.Message {
	mi := &file_proto_types_state_data_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CandidateV2.ProtoReflect.Descriptor instead.
func (*CandidateV2) Descriptor() ([]byte, []int) {
	return file_proto_types_state_data_proto_rawDescGZIP(), []int{3}
}

func (x *CandidateV2) GetOwnerAddress() string {
	if x != nil {
		return x.OwnerAddress
	}
	return ""
}

func (x *CandidateV2) GetOperatorAddress() string {
	if x != nil {
		return x.OperatorAddress
	}
	return ""
}

func (x *CandidateV2) GetRewardAddress() string {
	if x != nil {
		return x.RewardAddress
	}
	return ""
}

func (x *CandidateV2) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *CandidateV2) GetTotalWeightedVotes() string {
	if x != nil {
		return x.TotalWeightedVotes
	}
	return ""
}

func (x *CandidateV2) GetSelfStakeBucketIdx() uint64 {
	if x != nil {
		return x.SelfStakeBucketIdx
	}
	return 0
}

func (x *CandidateV2) GetSelfStakingTokens() string {
	if x != nil {
		return x.SelfStakingTokens
	}
	return ""
}

func (x *CandidateV2) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

type CandidateListV2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Candidates []*CandidateV2 `protobuf:"bytes,1,rep,name=candidates,proto3" json:"candidates,omitempty"`
}

func (x *CandidateListV2) Reset() {
	*x = CandidateListV2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_types_state_data_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CandidateListV2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CandidateListV2) ProtoMessage() {}

func (x *CandidateListV2) ProtoReflect() protoreflect.Message {
	mi := &file_proto_types_state_data_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CandidateListV2.ProtoReflect.Descriptor instead.
func (*CandidateListV2) Descriptor() ([]byte, []int) {
	return file_proto_types_state_data_proto_rawDescGZIP(), []int{4}
}

func (x *CandidateListV2) GetCandidates() []*CandidateV2 {
	if x != nil {
		return x.Candidates
	}
	return nil
}

type BucketsCount struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Total  uint64 `protobuf:"varint,1,opt,name=total,proto3" json:"total,omitempty"`
	Active uint64 `protobuf:"varint,2,opt,name=active,proto3" json:"active,omitempty"`
}

func (x *BucketsCount) Reset() {
	*x = BucketsCount{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_types_state_data_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *BucketsCount) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BucketsCount) ProtoMessage() {}

func (x *BucketsCount) ProtoReflect() protoreflect.Message {
	mi := &file_proto_types_state_data_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BucketsCount.ProtoReflect.Descriptor instead.
func (*BucketsCount) Descriptor() ([]byte, []int) {
	return file_proto_types_state_data_proto_rawDescGZIP(), []int{5}
}

func (x *BucketsCount) GetTotal() uint64 {
	if x != nil {
		return x.Total
	}
	return 0
}

func (x *BucketsCount) GetActive() uint64 {
	if x != nil {
		return x.Active
	}
	return 0
}

type ContractStakingBucketType struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	StakedAmount   string `protobuf:"bytes,1,opt,name=stakedAmount,proto3" json:"stakedAmount,omitempty"`
	StakedDuration uint32 `protobuf:"varint,2,opt,name=stakedDuration,proto3" json:"stakedDuration,omitempty"`
}

func (x *ContractStakingBucketType) Reset() {
	*x = ContractStakingBucketType{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_types_state_data_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ContractStakingBucketType) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ContractStakingBucketType) ProtoMessage() {}

func (x *ContractStakingBucketType) ProtoReflect() protoreflect.Message {
	mi := &file_proto_types_state_data_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ContractStakingBucketType.ProtoReflect.Descriptor instead.
func (*ContractStakingBucketType) Descriptor() ([]byte, []int) {
	return file_proto_types_state_data_proto_rawDescGZIP(), []int{6}
}

func (x *ContractStakingBucketType) GetStakedAmount() string {
	if x != nil {
		return x.StakedAmount
	}
	return ""
}

func (x *ContractStakingBucketType) GetStakedDuration() uint32 {
	if x != nil {
		return x.StakedDuration
	}
	return 0
}

type ContractStakingBucketTypeList struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	BucketTypes []*ContractStakingBucketType `protobuf:"bytes,1,rep,name=bucketTypes,proto3" json:"bucketTypes,omitempty"`
}

func (x *ContractStakingBucketTypeList) Reset() {
	*x = ContractStakingBucketTypeList{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_types_state_data_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ContractStakingBucketTypeList) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ContractStakingBucketTypeList) ProtoMessage() {}

func (x *ContractStakingBucketTypeList) ProtoReflect() protoreflect.Message {
	mi := &file_proto_types_state_data_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ContractStakingBucketTypeList.ProtoReflect.Descriptor instead.
func (*ContractStakingBucketTypeList) Descriptor() ([]byte, []int) {
	return file_proto_types_state_data_proto_rawDescGZIP(), []int{7}
}

func (x *ContractStakingBucketTypeList) GetBucketTypes() []*ContractStakingBucketType {
	if x != nil {
		return x.BucketTypes
	}
	return nil
}

type ProbationCandidateList_Info struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Address string `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	Count   uint32 `protobuf:"varint,2,opt,name=count,proto3" json:"count,omitempty"`
}

func (x *ProbationCandidateList_Info) Reset() {
	*x = ProbationCandidateList_Info{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_types_state_data_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ProbationCandidateList_Info) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProbationCandidateList_Info) ProtoMessage() {}

func (x *ProbationCandidateList_Info) ProtoReflect() protoreflect.Message {
	mi := &file_proto_types_state_data_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProbationCandidateList_Info.ProtoReflect.Descriptor instead.
func (*ProbationCandidateList_Info) Descriptor() ([]byte, []int) {
	return file_proto_types_state_data_proto_rawDescGZIP(), []int{0, 0}
}

func (x *ProbationCandidateList_Info) GetAddress() string {
	if x != nil {
		return x.Address
	}
	return ""
}

func (x *ProbationCandidateList_Info) GetCount() uint32 {
	if x != nil {
		return x.Count
	}
	return 0
}

var File_proto_types_state_data_proto protoreflect.FileDescriptor

var file_proto_types_state_data_proto_rawDesc = []byte{
	0x0a, 0x1c, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2f, 0x73, 0x74,
	0x61, 0x74, 0x65, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0a,
	0x69, 0x6f, 0x74, 0x65, 0x78, 0x74, 0x79, 0x70, 0x65, 0x73, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xc5, 0x01, 0x0a, 0x16,
	0x50, 0x72, 0x6f, 0x62, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x61, 0x6e, 0x64, 0x69, 0x64, 0x61,
	0x74, 0x65, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x4d, 0x0a, 0x0d, 0x70, 0x72, 0x6f, 0x62, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x4c, 0x69, 0x73, 0x74, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x27, 0x2e,
	0x69, 0x6f, 0x74, 0x65, 0x78, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x50, 0x72, 0x6f, 0x62, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x43, 0x61, 0x6e, 0x64, 0x69, 0x64, 0x61, 0x74, 0x65, 0x4c, 0x69, 0x73,
	0x74, 0x2e, 0x49, 0x6e, 0x66, 0x6f, 0x52, 0x0d, 0x70, 0x72, 0x6f, 0x62, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x24, 0x0a, 0x0d, 0x69, 0x6e, 0x74, 0x65, 0x6e, 0x73, 0x69,
	0x74, 0x79, 0x52, 0x61, 0x74, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0d, 0x69, 0x6e,
	0x74, 0x65, 0x6e, 0x73, 0x69, 0x74, 0x79, 0x52, 0x61, 0x74, 0x65, 0x1a, 0x36, 0x0a, 0x04, 0x49,
	0x6e, 0x66, 0x6f, 0x12, 0x18, 0x0a, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x14, 0x0a,
	0x05, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x63, 0x6f,
	0x75, 0x6e, 0x74, 0x22, 0xe0, 0x05, 0x0a, 0x0a, 0x56, 0x6f, 0x74, 0x65, 0x42, 0x75, 0x63, 0x6b,
	0x65, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x04, 0x52, 0x05, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x12, 0x2a, 0x0a, 0x10, 0x63, 0x61, 0x6e, 0x64,
	0x69, 0x64, 0x61, 0x74, 0x65, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x10, 0x63, 0x61, 0x6e, 0x64, 0x69, 0x64, 0x61, 0x74, 0x65, 0x41, 0x64, 0x64,
	0x72, 0x65, 0x73, 0x73, 0x12, 0x22, 0x0a, 0x0c, 0x73, 0x74, 0x61, 0x6b, 0x65, 0x64, 0x41, 0x6d,
	0x6f, 0x75, 0x6e, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x73, 0x74, 0x61, 0x6b,
	0x65, 0x64, 0x41, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x26, 0x0a, 0x0e, 0x73, 0x74, 0x61, 0x6b,
	0x65, 0x64, 0x44, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x0e, 0x73, 0x74, 0x61, 0x6b, 0x65, 0x64, 0x44, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x12, 0x3a, 0x0a, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x18, 0x05,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
	0x52, 0x0a, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x42, 0x0a, 0x0e,
	0x73, 0x74, 0x61, 0x6b, 0x65, 0x53, 0x74, 0x61, 0x72, 0x74, 0x54, 0x69, 0x6d, 0x65, 0x18, 0x06,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
	0x52, 0x0e, 0x73, 0x74, 0x61, 0x6b, 0x65, 0x53, 0x74, 0x61, 0x72, 0x74, 0x54, 0x69, 0x6d, 0x65,
	0x12, 0x46, 0x0a, 0x10, 0x75, 0x6e, 0x73, 0x74, 0x61, 0x6b, 0x65, 0x53, 0x74, 0x61, 0x72, 0x74,
	0x54, 0x69, 0x6d, 0x65, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x10, 0x75, 0x6e, 0x73, 0x74, 0x61, 0x6b, 0x65, 0x53,
	0x74, 0x61, 0x72, 0x74, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x61, 0x75, 0x74, 0x6f,
	0x53, 0x74, 0x61, 0x6b, 0x65, 0x18, 0x08, 0x20, 0x01, 0x28, 0x08, 0x52, 0x09, 0x61, 0x75, 0x74,
	0x6f, 0x53, 0x74, 0x61, 0x6b, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x6f, 0x77, 0x6e, 0x65, 0x72, 0x18,
	0x09, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6f, 0x77, 0x6e, 0x65, 0x72, 0x12, 0x28, 0x0a, 0x0f,
	0x63, 0x6f, 0x6e, 0x74, 0x72, 0x61, 0x63, 0x74, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18,
	0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x61, 0x63, 0x74, 0x41,
	0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x3c, 0x0a, 0x19, 0x73, 0x74, 0x61, 0x6b, 0x65, 0x64,
	0x44, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x4e, 0x75, 0x6d,
	0x62, 0x65, 0x72, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x04, 0x52, 0x19, 0x73, 0x74, 0x61, 0x6b, 0x65,
	0x64, 0x44, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x4e, 0x75,
	0x6d, 0x62, 0x65, 0x72, 0x12, 0x2c, 0x0a, 0x11, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x42, 0x6c,
	0x6f, 0x63, 0x6b, 0x48, 0x65, 0x69, 0x67, 0x68, 0x74, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x04, 0x52,
	0x11, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x48, 0x65, 0x69, 0x67,
	0x68, 0x74, 0x12, 0x34, 0x0a, 0x15, 0x73, 0x74, 0x61, 0x6b, 0x65, 0x53, 0x74, 0x61, 0x72, 0x74,
	0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x48, 0x65, 0x69, 0x67, 0x68, 0x74, 0x18, 0x0d, 0x20, 0x01, 0x28,
	0x04, 0x52, 0x15, 0x73, 0x74, 0x61, 0x6b, 0x65, 0x53, 0x74, 0x61, 0x72, 0x74, 0x42, 0x6c, 0x6f,
	0x63, 0x6b, 0x48, 0x65, 0x69, 0x67, 0x68, 0x74, 0x12, 0x38, 0x0a, 0x17, 0x75, 0x6e, 0x73, 0x74,
	0x61, 0x6b, 0x65, 0x53, 0x74, 0x61, 0x72, 0x74, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x48, 0x65, 0x69,
	0x67, 0x68, 0x74, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x04, 0x52, 0x17, 0x75, 0x6e, 0x73, 0x74, 0x61,
	0x6b, 0x65, 0x53, 0x74, 0x61, 0x72, 0x74, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x48, 0x65, 0x69, 0x67,
	0x68, 0x74, 0x12, 0x42, 0x0a, 0x1c, 0x65, 0x6e, 0x64, 0x6f, 0x72, 0x73, 0x65, 0x6d, 0x65, 0x6e,
	0x74, 0x45, 0x78, 0x70, 0x69, 0x72, 0x65, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x48, 0x65, 0x69, 0x67,
	0x68, 0x74, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x04, 0x52, 0x1c, 0x65, 0x6e, 0x64, 0x6f, 0x72, 0x73,
	0x65, 0x6d, 0x65, 0x6e, 0x74, 0x45, 0x78, 0x70, 0x69, 0x72, 0x65, 0x42, 0x6c, 0x6f, 0x63, 0x6b,
	0x48, 0x65, 0x69, 0x67, 0x68, 0x74, 0x22, 0x42, 0x0a, 0x0e, 0x56, 0x6f, 0x74, 0x65, 0x42, 0x75,
	0x63, 0x6b, 0x65, 0x74, 0x4c, 0x69, 0x73, 0x74, 0x12, 0x30, 0x0a, 0x07, 0x62, 0x75, 0x63, 0x6b,
	0x65, 0x74, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x69, 0x6f, 0x74, 0x65,
	0x78, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x56, 0x6f, 0x74, 0x65, 0x42, 0x75, 0x63, 0x6b, 0x65,
	0x74, 0x52, 0x07, 0x62, 0x75, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x22, 0xb3, 0x02, 0x0a, 0x0b, 0x43,
	0x61, 0x6e, 0x64, 0x69, 0x64, 0x61, 0x74, 0x65, 0x56, 0x32, 0x12, 0x22, 0x0a, 0x0c, 0x6f, 0x77,
	0x6e, 0x65, 0x72, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0c, 0x6f, 0x77, 0x6e, 0x65, 0x72, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x28,
	0x0a, 0x0f, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73,
	0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0f, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x6f,
	0x72, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x24, 0x0a, 0x0d, 0x72, 0x65, 0x77, 0x61,
	0x72, 0x64, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x0d, 0x72, 0x65, 0x77, 0x61, 0x72, 0x64, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x12,
	0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61,
	0x6d, 0x65, 0x12, 0x2e, 0x0a, 0x12, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x57, 0x65, 0x69, 0x67, 0x68,
	0x74, 0x65, 0x64, 0x56, 0x6f, 0x74, 0x65, 0x73, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x12,
	0x74, 0x6f, 0x74, 0x61, 0x6c, 0x57, 0x65, 0x69, 0x67, 0x68, 0x74, 0x65, 0x64, 0x56, 0x6f, 0x74,
	0x65, 0x73, 0x12, 0x2e, 0x0a, 0x12, 0x73, 0x65, 0x6c, 0x66, 0x53, 0x74, 0x61, 0x6b, 0x65, 0x42,
	0x75, 0x63, 0x6b, 0x65, 0x74, 0x49, 0x64, 0x78, 0x18, 0x06, 0x20, 0x01, 0x28, 0x04, 0x52, 0x12,
	0x73, 0x65, 0x6c, 0x66, 0x53, 0x74, 0x61, 0x6b, 0x65, 0x42, 0x75, 0x63, 0x6b, 0x65, 0x74, 0x49,
	0x64, 0x78, 0x12, 0x2c, 0x0a, 0x11, 0x73, 0x65, 0x6c, 0x66, 0x53, 0x74, 0x61, 0x6b, 0x69, 0x6e,
	0x67, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x73, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x11, 0x73,
	0x65, 0x6c, 0x66, 0x53, 0x74, 0x61, 0x6b, 0x69, 0x6e, 0x67, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x73,
	0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64,
	0x22, 0x4a, 0x0a, 0x0f, 0x43, 0x61, 0x6e, 0x64, 0x69, 0x64, 0x61, 0x74, 0x65, 0x4c, 0x69, 0x73,
	0x74, 0x56, 0x32, 0x12, 0x37, 0x0a, 0x0a, 0x63, 0x61, 0x6e, 0x64, 0x69, 0x64, 0x61, 0x74, 0x65,
	0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x69, 0x6f, 0x74, 0x65, 0x78, 0x74,
	0x79, 0x70, 0x65, 0x73, 0x2e, 0x43, 0x61, 0x6e, 0x64, 0x69, 0x64, 0x61, 0x74, 0x65, 0x56, 0x32,
	0x52, 0x0a, 0x63, 0x61, 0x6e, 0x64, 0x69, 0x64, 0x61, 0x74, 0x65, 0x73, 0x22, 0x3c, 0x0a, 0x0c,
	0x42, 0x75, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x14, 0x0a, 0x05,
	0x74, 0x6f, 0x74, 0x61, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x05, 0x74, 0x6f, 0x74,
	0x61, 0x6c, 0x12, 0x16, 0x0a, 0x06, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x04, 0x52, 0x06, 0x61, 0x63, 0x74, 0x69, 0x76, 0x65, 0x22, 0x67, 0x0a, 0x19, 0x43, 0x6f,
	0x6e, 0x74, 0x72, 0x61, 0x63, 0x74, 0x53, 0x74, 0x61, 0x6b, 0x69, 0x6e, 0x67, 0x42, 0x75, 0x63,
	0x6b, 0x65, 0x74, 0x54, 0x79, 0x70, 0x65, 0x12, 0x22, 0x0a, 0x0c, 0x73, 0x74, 0x61, 0x6b, 0x65,
	0x64, 0x41, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x73,
	0x74, 0x61, 0x6b, 0x65, 0x64, 0x41, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x26, 0x0a, 0x0e, 0x73,
	0x74, 0x61, 0x6b, 0x65, 0x64, 0x44, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x0e, 0x73, 0x74, 0x61, 0x6b, 0x65, 0x64, 0x44, 0x75, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x22, 0x68, 0x0a, 0x1d, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x61, 0x63, 0x74, 0x53,
	0x74, 0x61, 0x6b, 0x69, 0x6e, 0x67, 0x42, 0x75, 0x63, 0x6b, 0x65, 0x74, 0x54, 0x79, 0x70, 0x65,
	0x4c, 0x69, 0x73, 0x74, 0x12, 0x47, 0x0a, 0x0b, 0x62, 0x75, 0x63, 0x6b, 0x65, 0x74, 0x54, 0x79,
	0x70, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x25, 0x2e, 0x69, 0x6f, 0x74, 0x65,
	0x78, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x43, 0x6f, 0x6e, 0x74, 0x72, 0x61, 0x63, 0x74, 0x53,
	0x74, 0x61, 0x6b, 0x69, 0x6e, 0x67, 0x42, 0x75, 0x63, 0x6b, 0x65, 0x74, 0x54, 0x79, 0x70, 0x65,
	0x52, 0x0b, 0x62, 0x75, 0x63, 0x6b, 0x65, 0x74, 0x54, 0x79, 0x70, 0x65, 0x73, 0x42, 0x5d, 0x0a,
	0x22, 0x63, 0x6f, 0x6d, 0x2e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x69, 0x6f, 0x74, 0x65,
	0x78, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x2e, 0x67, 0x72, 0x70, 0x63, 0x2e, 0x74, 0x79,
	0x70, 0x65, 0x73, 0x50, 0x01, 0x5a, 0x35, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f,
	0x6d, 0x2f, 0x69, 0x6f, 0x74, 0x65, 0x78, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, 0x2f, 0x69,
	0x6f, 0x74, 0x65, 0x78, 0x2d, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x6c, 0x61, 0x6e,
	0x67, 0x2f, 0x69, 0x6f, 0x74, 0x65, 0x78, 0x74, 0x79, 0x70, 0x65, 0x73, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_proto_types_state_data_proto_rawDescOnce sync.Once
	file_proto_types_state_data_proto_rawDescData = file_proto_types_state_data_proto_rawDesc
)

func file_proto_types_state_data_proto_rawDescGZIP() []byte {
	file_proto_types_state_data_proto_rawDescOnce.Do(func() {
		file_proto_types_state_data_proto_rawDescData = protoimpl.X.CompressGZIP(file_proto_types_state_data_proto_rawDescData)
	})
	return file_proto_types_state_data_proto_rawDescData
}

var file_proto_types_state_data_proto_msgTypes = make([]protoimpl.MessageInfo, 9)
var file_proto_types_state_data_proto_goTypes = []any{
	(*ProbationCandidateList)(nil),        // 0: iotextypes.ProbationCandidateList
	(*VoteBucket)(nil),                    // 1: iotextypes.VoteBucket
	(*VoteBucketList)(nil),                // 2: iotextypes.VoteBucketList
	(*CandidateV2)(nil),                   // 3: iotextypes.CandidateV2
	(*CandidateListV2)(nil),               // 4: iotextypes.CandidateListV2
	(*BucketsCount)(nil),                  // 5: iotextypes.BucketsCount
	(*ContractStakingBucketType)(nil),     // 6: iotextypes.ContractStakingBucketType
	(*ContractStakingBucketTypeList)(nil), // 7: iotextypes.ContractStakingBucketTypeList
	(*ProbationCandidateList_Info)(nil),   // 8: iotextypes.ProbationCandidateList.Info
	(*timestamppb.Timestamp)(nil),         // 9: google.protobuf.Timestamp
}
var file_proto_types_state_data_proto_depIdxs = []int32{
	8, // 0: iotextypes.ProbationCandidateList.probationList:type_name -> iotextypes.ProbationCandidateList.Info
	9, // 1: iotextypes.VoteBucket.createTime:type_name -> google.protobuf.Timestamp
	9, // 2: iotextypes.VoteBucket.stakeStartTime:type_name -> google.protobuf.Timestamp
	9, // 3: iotextypes.VoteBucket.unstakeStartTime:type_name -> google.protobuf.Timestamp
	1, // 4: iotextypes.VoteBucketList.buckets:type_name -> iotextypes.VoteBucket
	3, // 5: iotextypes.CandidateListV2.candidates:type_name -> iotextypes.CandidateV2
	6, // 6: iotextypes.ContractStakingBucketTypeList.bucketTypes:type_name -> iotextypes.ContractStakingBucketType
	7, // [7:7] is the sub-list for method output_type
	7, // [7:7] is the sub-list for method input_type
	7, // [7:7] is the sub-list for extension type_name
	7, // [7:7] is the sub-list for extension extendee
	0, // [0:7] is the sub-list for field type_name
}

func init() { file_proto_types_state_data_proto_init() }
func file_proto_types_state_data_proto_init() {
	if File_proto_types_state_data_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_proto_types_state_data_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*ProbationCandidateList); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_types_state_data_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*VoteBucket); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_types_state_data_proto_msgTypes[2].Exporter = func(v any, i int) any {
			switch v := v.(*VoteBucketList); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_types_state_data_proto_msgTypes[3].Exporter = func(v any, i int) any {
			switch v := v.(*CandidateV2); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_types_state_data_proto_msgTypes[4].Exporter = func(v any, i int) any {
			switch v := v.(*CandidateListV2); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_types_state_data_proto_msgTypes[5].Exporter = func(v any, i int) any {
			switch v := v.(*BucketsCount); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_types_state_data_proto_msgTypes[6].Exporter = func(v any, i int) any {
			switch v := v.(*ContractStakingBucketType); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_types_state_data_proto_msgTypes[7].Exporter = func(v any, i int) any {
			switch v := v.(*ContractStakingBucketTypeList); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_types_state_data_proto_msgTypes[8].Exporter = func(v any, i int) any {
			switch v := v.(*ProbationCandidateList_Info); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_proto_types_state_data_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   9,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_proto_types_state_data_proto_goTypes,
		DependencyIndexes: file_proto_types_state_data_proto_depIdxs,
		MessageInfos:      file_proto_types_state_data_proto_msgTypes,
	}.Build()
	File_proto_types_state_data_proto = out.File
	file_proto_types_state_data_proto_rawDesc = nil
	file_proto_types_state_data_proto_goTypes = nil
	file_proto_types_state_data_proto_depIdxs = nil
}
