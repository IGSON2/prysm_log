package types

import (
	types "github.com/prysmaticlabs/prysm/v3/consensus-types/primitives"
	ethpb "github.com/prysmaticlabs/prysm/v3/proto/prysm/v1alpha1"
)

// ChunkKind to differentiate what kind of span we are working
// with for slashing detection, either min or max span.
type ChunkKind uint

const (
	MinSpan ChunkKind = iota
	MaxSpan
)

// IndexedAttestationWrapper contains an indexed attestation with its
// signing root to reduce duplicated computation.
//
// IndexedAttestationWrapper에는 중복 계산을 줄이기 위해 서명 루트와 함께 인덱싱된 증명이 포함되어 있습니다.
type IndexedAttestationWrapper struct {
	IndexedAttestation *ethpb.IndexedAttestation
	SigningRoot        [32]byte
}

// AttesterDoubleVote represents a double vote instance
// which is a slashable event for attesters.
type AttesterDoubleVote struct {
	Target                 types.Epoch
	ValidatorIndex         types.ValidatorIndex
	PrevAttestationWrapper *IndexedAttestationWrapper
	AttestationWrapper     *IndexedAttestationWrapper
}

// DoubleBlockProposal containing an incoming and an existing proposal's signing root.
type DoubleBlockProposal struct {
	Slot                   types.Slot
	ValidatorIndex         types.ValidatorIndex
	PrevBeaconBlockWrapper *SignedBlockHeaderWrapper
	BeaconBlockWrapper     *SignedBlockHeaderWrapper
}

// SignedBlockHeaderWrapper contains an signed beacon block header with its
// signing root to reduce duplicated computation.
//
// SignedBlockHeaderWrapper는 중복 계산을 줄이기 위해 서명 루트가 있는 서명된 비콘 블록 헤더를 포함합니다.
type SignedBlockHeaderWrapper struct {
	SignedBeaconBlockHeader *ethpb.SignedBeaconBlockHeader
	SigningRoot             [32]byte
}

// AttestedEpochForValidator encapsulates a previously attested epoch
// for a validator index.
type AttestedEpochForValidator struct {
	ValidatorIndex types.ValidatorIndex
	Epoch          types.Epoch
}
