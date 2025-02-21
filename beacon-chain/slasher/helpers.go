package slasher

import (
	"bytes"
	"strconv"

	slashertypes "github.com/prysmaticlabs/prysm/v3/beacon-chain/slasher/types"
	fieldparams "github.com/prysmaticlabs/prysm/v3/config/fieldparams"
	"github.com/prysmaticlabs/prysm/v3/config/params"
	types "github.com/prysmaticlabs/prysm/v3/consensus-types/primitives"
	"github.com/prysmaticlabs/prysm/v3/container/slice"
	ethpb "github.com/prysmaticlabs/prysm/v3/proto/prysm/v1alpha1"
	"github.com/sirupsen/logrus"
)

// Group a list of attestations into batches by validator chunk index.
// This way, we can detect on the batch of attestations for each validator chunk index
// concurrently, and also allowing us to effectively use a single 2D chunk
// for slashing detection through this logical grouping.
func (s *Service) groupByValidatorChunkIndex(
	attestations []*slashertypes.IndexedAttestationWrapper,
) map[uint64][]*slashertypes.IndexedAttestationWrapper {
	groupedAttestations := make(map[uint64][]*slashertypes.IndexedAttestationWrapper)
	for _, att := range attestations {
		validatorChunkIndices := make(map[uint64]bool)
		for _, validatorIdx := range att.IndexedAttestation.AttestingIndices {
			validatorChunkIndex := s.params.validatorChunkIndex(types.ValidatorIndex(validatorIdx))
			validatorChunkIndices[validatorChunkIndex] = true
		}
		for validatorChunkIndex := range validatorChunkIndices {
			groupedAttestations[validatorChunkIndex] = append(
				groupedAttestations[validatorChunkIndex],
				att,
			)
		}
	}
	return groupedAttestations
}

// Group attestations by the chunk index their source epoch corresponds to.
func (s *Service) groupByChunkIndex(
	attestations []*slashertypes.IndexedAttestationWrapper,
) map[uint64][]*slashertypes.IndexedAttestationWrapper {
	attestationsByChunkIndex := make(map[uint64][]*slashertypes.IndexedAttestationWrapper)
	for _, att := range attestations {
		chunkIdx := s.params.chunkIndex(att.IndexedAttestation.Data.Source.Epoch)
		attestationsByChunkIndex[chunkIdx] = append(attestationsByChunkIndex[chunkIdx], att)
	}
	return attestationsByChunkIndex
}

// This function returns a list of valid attestations, a list of attestations that are
// valid in the future, and the number of attestations dropped.
func (s *Service) filterAttestations(
	atts []*slashertypes.IndexedAttestationWrapper, currentEpoch types.Epoch,
) (valid, validInFuture []*slashertypes.IndexedAttestationWrapper, numDropped int) {
	valid = make([]*slashertypes.IndexedAttestationWrapper, 0, len(atts))
	validInFuture = make([]*slashertypes.IndexedAttestationWrapper, 0, len(atts))

	for _, attWrapper := range atts {
		if attWrapper == nil || !validateAttestationIntegrity(attWrapper.IndexedAttestation) {
			numDropped++
			continue
		}

		// If an attestation's source is epoch is older than the max history length
		// we keep track of for slashing detection, we drop it.
		if attWrapper.IndexedAttestation.Data.Source.Epoch+s.params.historyLength <= currentEpoch {
			numDropped++
			continue
		}

		// If an attestations's target epoch is in the future, we defer processing for later.
		if attWrapper.IndexedAttestation.Data.Target.Epoch > currentEpoch {
			validInFuture = append(validInFuture, attWrapper)
		} else {
			valid = append(valid, attWrapper)
		}
	}
	return
}

// Validates the attestation data integrity, ensuring we have no nil values for
// source, epoch, and that the source epoch of the attestation must be less than
// the target epoch, which is a precondition for performing slashing detection.
// This function also checks the attestation source epoch is within the history size
// we keep track of for slashing detection.
//
// 증명 데이터 무결성을 검증하고 소스값, 에포크가 nil이 아님을 보증한다,
// 그리고 증명의 소스 에포크는 반드시 슬래싱 감지를 수행하기 위한 전제조건인 타겟 에포크보다 작아야 한다.
// 이 함수는 또한 슬래시 탐지를 위해 추적하는 기록 크기 내에 증명 소스 에포크가 있는지 확인합니다.
func validateAttestationIntegrity(att *ethpb.IndexedAttestation) bool {
	// If an attestation is malformed, we drop it.
	if att == nil ||
		att.Data == nil ||
		att.Data.Source == nil ||
		att.Data.Target == nil {
		return false
	}

	sourceEpoch := att.Data.Source.Epoch
	targetEpoch := att.Data.Target.Epoch

	// The genesis epoch is a special case, since all attestations formed in it
	// will have source and target 0, and they should be considered valid.
	if sourceEpoch == 0 && targetEpoch == 0 {
		return true
	}

	// All valid attestations must have source epoch < target epoch.
	return sourceEpoch < targetEpoch
}

// Validates the signed beacon block header integrity, ensuring we have no nil values.
//
// 서명된 비콘 블록 헤더 무결성을 확인하여 0 값이 없는지 확인합니다.
func validateBlockHeaderIntegrity(header *ethpb.SignedBeaconBlockHeader) bool {
	// If a signed block header is malformed, we drop it.
	if header == nil ||
		header.Header == nil ||
		len(header.Signature) != fieldparams.BLSSignatureLength ||
		bytes.Equal(header.Signature, make([]byte, fieldparams.BLSSignatureLength)) {
		return false
	}
	return true
}

func logAttesterSlashing(slashing *ethpb.AttesterSlashing) {
	indices := slice.IntersectionUint64(slashing.Attestation_1.AttestingIndices, slashing.Attestation_2.AttestingIndices)
	log.WithFields(logrus.Fields{
		"validatorIndex":  indices,
		"prevSourceEpoch": slashing.Attestation_1.Data.Source.Epoch,
		"prevTargetEpoch": slashing.Attestation_1.Data.Target.Epoch,
		"sourceEpoch":     slashing.Attestation_2.Data.Source.Epoch,
		"targetEpoch":     slashing.Attestation_2.Data.Target.Epoch,
	}).Info("Attester slashing detected")
}

func logProposerSlashing(slashing *ethpb.ProposerSlashing) {
	log.WithFields(logrus.Fields{
		"validatorIndex": slashing.Header_1.Header.ProposerIndex,
		"slot":           slashing.Header_1.Header.Slot,
	}).Info("Proposer slashing detected")
}

// Turns a uint64 value to a string representation.
func uintToString(val uint64) string {
	return strconv.FormatUint(val, 10)
}

// If an existing signing root does not match an incoming proposal signing root,
// we then have a double block proposer slashing event.
func isDoubleProposal(incomingSigningRoot, existingSigningRoot [32]byte) bool {
	// If the existing signing root is the zero hash, we do not consider
	// this a double proposal.
	if existingSigningRoot == params.BeaconConfig().ZeroHash {
		return false
	}
	return incomingSigningRoot != existingSigningRoot
}
