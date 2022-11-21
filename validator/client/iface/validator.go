package iface

import (
	"context"
	"errors"
	"time"

	fieldparams "github.com/prysmaticlabs/prysm/v3/config/fieldparams"
	types "github.com/prysmaticlabs/prysm/v3/consensus-types/primitives"
	"github.com/prysmaticlabs/prysm/v3/crypto/bls"
	ethpb "github.com/prysmaticlabs/prysm/v3/proto/prysm/v1alpha1"
	validatorpb "github.com/prysmaticlabs/prysm/v3/proto/prysm/v1alpha1/validator-client"
	"github.com/prysmaticlabs/prysm/v3/validator/keymanager"
)

// ErrConnectionIssue represents a connection problem.
var ErrConnectionIssue = errors.New("could not connect")

// ValidatorRole defines the validator role.
type ValidatorRole int8

const (
	// RoleUnknown means that the role of the validator cannot be determined.
	//
	// 확인할 수 없는 검증자
	RoleUnknown ValidatorRole = iota

	// RoleAttester means that the validator should submit an attestation.
	//
	// 증명을 제출해야 하는 검증자
	RoleAttester

	// RoleProposer means that the validator should propose a block.
	//
	// 블록을 제안해야 하는 검증자
	RoleProposer

	// RoleAggregator means that the validator should submit an aggregation and proof.
	//
	// 집계 및 증명을 제출해야 하는 검증자
	RoleAggregator

	// RoleSyncCommittee means that the validator should submit a sync committee message.
	//
	// 동기화 위원회(?) 메시지를 제출해야 하는 검증자
	RoleSyncCommittee

	// RoleSyncCommitteeAggregator means the valiator should aggregate sync committee messages and submit a sync committee contribution.
	//
	// 동기화 위원회 미시지를 집계하고 동기화 위원회 기여도를 제출해야 하는 검증자
	RoleSyncCommitteeAggregator
)

// Validator interface defines the primary methods of a validator client.
type Validator interface {
	Done()
	WaitForChainStart(ctx context.Context) error
	WaitForSync(ctx context.Context) error
	WaitForActivation(ctx context.Context, accountsChangedChan chan [][fieldparams.BLSPubkeyLength]byte) error
	CanonicalHeadSlot(ctx context.Context) (types.Slot, error)
	NextSlot() <-chan types.Slot
	SlotDeadline(slot types.Slot) time.Time
	LogValidatorGainsAndLosses(ctx context.Context, slot types.Slot) error
	UpdateDuties(ctx context.Context, slot types.Slot) error
	RolesAt(ctx context.Context, slot types.Slot) (map[[fieldparams.BLSPubkeyLength]byte][]ValidatorRole, error) // validator pubKey -> roles
	SubmitAttestation(ctx context.Context, slot types.Slot, pubKey [fieldparams.BLSPubkeyLength]byte)
	ProposeBlock(ctx context.Context, slot types.Slot, pubKey [fieldparams.BLSPubkeyLength]byte)
	SubmitAggregateAndProof(ctx context.Context, slot types.Slot, pubKey [fieldparams.BLSPubkeyLength]byte)
	SubmitSyncCommitteeMessage(ctx context.Context, slot types.Slot, pubKey [fieldparams.BLSPubkeyLength]byte)
	SubmitSignedContributionAndProof(ctx context.Context, slot types.Slot, pubKey [fieldparams.BLSPubkeyLength]byte)
	LogAttestationsSubmitted()
	LogSyncCommitteeMessagesSubmitted()
	UpdateDomainDataCaches(ctx context.Context, slot types.Slot)
	WaitForKeymanagerInitialization(ctx context.Context) error
	AllValidatorsAreExited(ctx context.Context) (bool, error)
	Keymanager() (keymanager.IKeymanager, error)
	ReceiveBlocks(ctx context.Context, connectionErrorChannel chan<- error)
	HandleKeyReload(ctx context.Context, newKeys [][fieldparams.BLSPubkeyLength]byte) (bool, error)
	CheckDoppelGanger(ctx context.Context) error
	HasProposerSettings() bool
	PushProposerSettings(ctx context.Context, km keymanager.IKeymanager) error
	SignValidatorRegistrationRequest(ctx context.Context, signer SigningFunc, newValidatorRegistration *ethpb.ValidatorRegistrationV1) (*ethpb.SignedValidatorRegistrationV1, error)
}

// SigningFunc interface defines a type for the a function that signs a message
type SigningFunc func(context.Context, *validatorpb.SignRequest) (bls.Signature, error)
