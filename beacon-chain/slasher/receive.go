package slasher

import (
	"context"
	"time"

	"github.com/pkg/errors"
	slashertypes "github.com/prysmaticlabs/prysm/v3/beacon-chain/slasher/types"
	types "github.com/prysmaticlabs/prysm/v3/consensus-types/primitives"
	ethpb "github.com/prysmaticlabs/prysm/v3/proto/prysm/v1alpha1"
	"github.com/prysmaticlabs/prysm/v3/time/slots"
	"github.com/sirupsen/logrus"
)

// Receive indexed attestations from some source event feed,
// validating their integrity before appending them to an attestation queue
// for batch processing in a separate routine.
//
// 일부 원본 이벤트 피드에서 인덱스된 증명을 수신하여 별도의 루틴에서
// 일괄 처리를 위해 증명 대기열에 추가하기 전에 무결성을 확인합니다.
func (s *Service) receiveAttestations(ctx context.Context, indexedAttsChan chan *ethpb.IndexedAttestation) {
	sub := s.serviceCfg.IndexedAttestationsFeed.Subscribe(indexedAttsChan)
	defer sub.Unsubscribe()
	for {
		select {
		case att := <-indexedAttsChan:
			if !validateAttestationIntegrity(att) {
				continue
			}
			signingRoot, err := att.Data.HashTreeRoot()
			if err != nil {
				log.WithError(err).Error("Could not get hash tree root of attestation")
				continue
			}
			attWrapper := &slashertypes.IndexedAttestationWrapper{
				IndexedAttestation: att,
				SigningRoot:        signingRoot,
			}
			s.attsQueue.push(attWrapper)
		case err := <-sub.Err():
			log.WithError(err).Debug("Subscriber closed with error")
			return
		case <-ctx.Done():
			return
		}
	}
}

// Receive beacon blocks from some source event feed,
func (s *Service) receiveBlocks(ctx context.Context, beaconBlockHeadersChan chan *ethpb.SignedBeaconBlockHeader) {
	sub := s.serviceCfg.BeaconBlockHeadersFeed.Subscribe(beaconBlockHeadersChan)
	defer sub.Unsubscribe()
	for {
		select {
		case blockHeader := <-beaconBlockHeadersChan:
			if !validateBlockHeaderIntegrity(blockHeader) {
				continue
			}
			signingRoot, err := blockHeader.Header.HashTreeRoot()
			if err != nil {
				log.WithError(err).Error("Could not get hash tree root of signed block header")
				continue
			}
			wrappedProposal := &slashertypes.SignedBlockHeaderWrapper{
				SignedBeaconBlockHeader: blockHeader,
				SigningRoot:             signingRoot,
			}
			s.blksQueue.push(wrappedProposal)
		case err := <-sub.Err():
			log.WithError(err).Debug("Subscriber closed with error")
			return
		case <-ctx.Done():
			return
		}
	}
}

// Process queued attestations every time a slot ticker fires. We retrieve
// these attestations from a queue, then group them all by validator chunk index.
// This grouping will allow us to perform detection on batches of attestations
// per validator chunk index which can be done concurrently.
//
// 슬롯 티커가 실행될 때마다 대기 중인 증명을 처리합니다. 큐에서 이러한 증명을 검색한 다음 검증자 청크 인덱스별로 모두 그룹화합니다.
// 이 그룹화를 통해 동시에 수행할 수 있는 검증자 청크 인덱스당 증명 배치에 대한 탐지를 수행할 수 있습니다.
func (s *Service) processQueuedAttestations(ctx context.Context, slotTicker <-chan types.Slot) {
	for {
		select {
		case currentSlot := <-slotTicker:
			attestations := s.attsQueue.dequeue()
			currentEpoch := slots.ToEpoch(currentSlot)
			// We take all the attestations in the queue and filter out
			// those which are valid now and valid in the future.
			validAtts, validInFuture, numDropped := s.filterAttestations(attestations, currentEpoch)

			deferredAttestationsTotal.Add(float64(len(validInFuture)))
			droppedAttestationsTotal.Add(float64(numDropped))

			// We add back those attestations that are valid in the future to the queue.
			s.attsQueue.extend(validInFuture)

			log.WithFields(logrus.Fields{
				"currentSlot":     currentSlot,
				"currentEpoch":    currentEpoch,
				"numValidAtts":    len(validAtts),
				"numDeferredAtts": len(validInFuture),
				"numDroppedAtts":  numDropped,
			}).Info("Processing queued attestations for slashing detection")

			// Save the attestation records to our database.
			if err := s.serviceCfg.Database.SaveAttestationRecordsForValidators(
				ctx, validAtts,
			); err != nil {
				log.WithError(err).Error("Could not save attestation records to DB")
				continue
			}

			// Check for slashings.
			slashings, err := s.checkSlashableAttestations(ctx, currentEpoch, validAtts)
			if err != nil {
				log.WithError(err).Error("Could not check slashable attestations")
				continue
			}

			// Process attester slashings by verifying their signatures, submitting
			// to the beacon node's operations pool, and logging them.
			// 서명을 확인하고 비콘 노드의 작업 풀에 제출한 다음 기록하여 증명인 슬래싱을 처리합니다.
			if err := s.processAttesterSlashings(ctx, slashings); err != nil {
				log.WithError(err).Error("Could not process attester slashings")
				continue
			}

			processedAttestationsTotal.Add(float64(len(validAtts)))
		case <-ctx.Done():
			return
		}
	}
}

// Process queued blocks every time an epoch ticker fires. We retrieve
// these blocks from a queue, then perform double proposal detection.
//
// 에포크 티커가 발생할 때마다 대기 중인 블록을 처리합니다.
// 큐에서 이러한 블록을 검색한 다음 이중 제안 탐지를 수행합니다.
func (s *Service) processQueuedBlocks(ctx context.Context, slotTicker <-chan types.Slot) {
	for {
		select {
		case currentSlot := <-slotTicker:
			blocks := s.blksQueue.dequeue()
			currentEpoch := slots.ToEpoch(currentSlot)

			receivedBlocksTotal.Add(float64(len(blocks)))

			log.WithFields(logrus.Fields{
				"currentSlot":  currentSlot,
				"currentEpoch": currentEpoch,
				"numBlocks":    len(blocks),
			}).Info("Processing queued blocks for slashing detection")

			start := time.Now()
			// Check for slashings.
			slashings, err := s.detectProposerSlashings(ctx, blocks)
			if err != nil {
				log.WithError(err).Error("Could not detect proposer slashings")
				continue
			}

			// Process proposer slashings by verifying their signatures, submitting
			// to the beacon node's operations pool, and logging them.
			if err := s.processProposerSlashings(ctx, slashings); err != nil {
				log.WithError(err).Error("Could not process proposer slashings")
				continue
			}

			log.WithField("elapsed", time.Since(start)).Debug("Done checking slashable blocks")

			processedBlocksTotal.Add(float64(len(blocks)))
		case <-ctx.Done():
			return
		}
	}
}

// Prunes slasher data on each slot tick to prevent unnecessary build-up of disk space usage.
//
// 디스크 공간의 불필요한 증가를 방지하기 위해 각 슬롯 눈금에 슬래셔 데이터를 제거합니다.
func (s *Service) pruneSlasherData(ctx context.Context, slotTicker <-chan types.Slot) {
	for {
		select {
		case <-slotTicker:
			headEpoch := slots.ToEpoch(s.serviceCfg.HeadStateFetcher.HeadSlot())
			if err := s.pruneSlasherDataWithinSlidingWindow(ctx, headEpoch); err != nil {
				log.WithError(err).Error("Could not prune slasher data")
				continue
			}
		case <-ctx.Done():
			return
		}
	}
}

// Prunes slasher data by using a sliding window of [current_epoch - HISTORY_LENGTH, current_epoch].
// All data before that window is unnecessary for slasher, so can be periodically deleted.
// Say HISTORY_LENGTH is 4 and we have data for epochs 0, 1, 2, 3. Once we hit epoch 4, the sliding window
// we care about is 1, 2, 3, 4, so we can delete data for epoch 0.
//
// [current_epoch - History_LENGTH, current_epoch]의 슬라이딩 창을 사용하여 슬래셔 데이터를 자릅니다.
// 슬래셔에는 해당 창 이전의 모든 데이터가 불필요하므로 주기적으로 삭제할 수 있습니다.
// HISTORY_LENGTH가 4이고 에포크 0, 1, 2, 3에 대한 데이터가 있습니다.
// 에포크 4에 도달하면 우리가 관심을 갖는 슬라이딩 윈도우는 1, 2, 3, 4이므로 에포크 0에 대한 데이터를 삭제할 수 있습니다.
func (s *Service) pruneSlasherDataWithinSlidingWindow(ctx context.Context, currentEpoch types.Epoch) error {
	var maxPruningEpoch types.Epoch
	if currentEpoch >= s.params.historyLength {
		maxPruningEpoch = currentEpoch - s.params.historyLength
	} else {
		// If the current epoch is less than the history length, we should not
		// attempt to prune at all.
		return nil
	}
	start := time.Now()
	log.WithFields(logrus.Fields{
		"currentEpoch":          currentEpoch,
		"pruningAllBeforeEpoch": maxPruningEpoch,
	}).Info("Pruning old attestations and proposals for slasher")
	numPrunedAtts, err := s.serviceCfg.Database.PruneAttestationsAtEpoch(
		ctx, maxPruningEpoch,
	)
	if err != nil {
		return errors.Wrap(err, "Could not prune attestations")
	}
	numPrunedProposals, err := s.serviceCfg.Database.PruneProposalsAtEpoch(
		ctx, maxPruningEpoch,
	)
	if err != nil {
		return errors.Wrap(err, "Could not prune proposals")
	}
	fields := logrus.Fields{}
	if numPrunedAtts > 0 {
		fields["numPrunedAtts"] = numPrunedAtts
	}
	if numPrunedProposals > 0 {
		fields["numPrunedProposals"] = numPrunedProposals
	}
	fields["elapsed"] = time.Since(start)
	log.WithFields(fields).Info("Done pruning old attestations and proposals for slasher")
	return nil
}
