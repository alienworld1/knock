package admission

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"knock/internal/chain"
	"knock/internal/lease"

	"github.com/ethereum/go-ethereum/common"
)

type revocationReader func(context.Context, []common.Hash) (chain.RevocationObservation, error)

type cleanupRetry struct {
	after time.Time
	delay time.Duration
}

func (h Host) ReconcileSSH(cause string, verified bool) error {
	sessions, err := h.Journal.sessions()
	if err != nil {
		return err
	}
	state := lease.CleanupIncomplete
	if verified {
		state = lease.Closed
	}
	for _, session := range sessions {
		if session.Record.State == lease.Closed {
			continue
		}
		changed, err := h.recordHostState(session.Request, lease.Observation{State: state, Cause: cause})
		if err != nil {
			return err
		}
		if changed {
			h.progress(session.Record.ID, string(state))
		}
	}
	return nil
}

func (h Host) MonitorSSH(ctx context.Context, observe revocationReader) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var latest chain.RevocationObservation
	retries := make(map[common.Hash]cleanupRetry)
	healthy, initialized, statusError := false, false, false
	for ctx.Err() == nil {
		sessions, err := h.Journal.sessions()
		if err != nil {
			return err
		}
		var active []common.Hash
		for _, session := range sessions {
			if state := session.Record.State; state != lease.Closed && state != lease.Closing && state != lease.CleanupIncomplete {
				active = append(active, session.Record.ID)
			}
		}
		call, cancel := context.WithTimeout(ctx, 8*time.Second)
		observation, chainErr := observe(call, active)
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		if observation.Height < latest.Height ||
			(observation.Height == latest.Height && observation.Block != latest.Block) {
			chainErr = errors.New("Diana finalized observation moved backward or changed")
			observation = chain.RevocationObservation{}
		}
		if observation.Height != 0 {
			latest.Height, latest.Block = observation.Height, observation.Block
		}
		if chainErr == nil {
			latest.Observed = observation.Observed
		}
		chainOK := chainErr == nil
		if !initialized || healthy != chainOK {
			if h.Progress != nil {
				if chainOK {
					h.Progress("Diana revocation monitoring available")
				} else {
					h.Progress("Diana revocation monitoring degraded. New access requires fresh verification.")
				}
			}
			healthy, initialized = chainOK, true
		}

		for _, session := range sessions {
			if session.Record.State == lease.Closed {
				continue
			}
			id := session.Record.ID
			revoked := slices.Contains(observation.Revoked, id)
			if err := h.updateMonitoring(session.Request, latest.Observed, chainOK, observation, revoked); err != nil {
				if revoked {
					call, stop := context.WithTimeout(context.Background(), 15*time.Second)
					defer stop()
					return errors.Join(err, h.SSH.Close(call, hex.EncodeToString(id[:])))
				}
				return err
			}
			if revoked {
				h.progress(id, fmt.Sprintf("Revocation observed in finalized block %s", observation.Block.Hex()))
			}
			if err := h.inspectSession(ctx, session, revoked, retries); err != nil {
				return err
			}
		}

		err = h.queueSessionStatus(ctx)
		if (err != nil) != statusError && h.Progress != nil {
			if err != nil {
				h.Progress("Couldn't prepare signed session status. Retrying.")
			} else {
				h.Progress("Signed session status resumed")
			}
		}
		statusError = err != nil
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
	return nil
}

func (h Host) updateMonitoring(request common.Hash, checked time.Time, healthy bool, observation chain.RevocationObservation, revoked bool) error {
	now := time.Now().Unix()
	_, err := h.Journal.editLease(request, func(item *entry) (bool, error) {
		if item.Lease.State == lease.Closed {
			return false, nil
		}
		e := item.Evidence
		if e != nil {
			if revoked {
				e.RevokedAt, e.RevokedBlock, e.Cause = observation.Observed.Unix(), observation.Block, "Revoked"
			}
			if revoked || e.Degraded == healthy || now-e.Changed >= int64(statusInterval/time.Second) || now < e.Changed {
				if !checked.IsZero() {
					e.ChainAt = checked.Unix()
				}
				e.Degraded = !healthy
				e.touch(now)
				if revoked {
					item.advance(lease.Closing, now)
				}
				return true, nil
			}
		}
		if revoked {
			return item.advance(lease.Closing, now), nil
		}
		return false, nil
	})
	return err
}

func (h Host) inspectSession(ctx context.Context, session journalSession, revoked bool, retries map[common.Hash]cleanupRetry) error {
	id, state := session.Record.ID, session.Record.State
	ref := hex.EncodeToString(id[:])
	retry := retries[id]
	call, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	observed, err := h.SSH.Observe(call, ref)
	if err != nil {
		return err
	}
	if observed.State == lease.Closed {
		delete(retries, id)
	} else if revoked || ((state == lease.Closing || state == lease.CleanupIncomplete ||
		observed.State == lease.Closing || observed.State == lease.CleanupIncomplete) && !time.Now().Before(retry.after)) {
		// Close is idempotent and verifies the applicable native postconditions.
		if err := h.SSH.Close(call, ref); err != nil {
			retry.delay = min(max(retry.delay*2, time.Second), 16*time.Second)
			retry.after = time.Now().Add(retry.delay)
			retries[id] = retry
			observed.State = lease.CleanupIncomplete
		} else {
			delete(retries, id)
			observed.State = lease.Closed
		}
	}
	switch observed.State {
	case lease.Active, lease.Closing, lease.Closed, lease.CleanupIncomplete:
		changed, err := h.recordHostState(session.Request, observed)
		if changed {
			stage := string(observed.State)
			if observed.State == lease.Closed && (revoked || (session.Evidence != nil && session.Evidence.RevokedAt != 0)) {
				stage = "Revocation enforced · Closed"
			}
			h.progress(id, stage)
		}
		return err
	}
	return nil
}

func (h Host) recordHostState(request common.Hash, observed lease.Observation) (bool, error) {
	return h.Journal.editLease(request, func(item *entry) (bool, error) {
		if item.Evidence != nil && item.Evidence.Cause == "" {
			item.Evidence.Cause = observed.Cause
		}
		return item.advance(observed.State, time.Now().Unix()), nil
	})
}
