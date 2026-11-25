package admission

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"knock/internal/lease"

	"github.com/ethereum/go-ethereum/common"
)

func (h Host) provision(ctx context.Context, body doorPayload, manifest, decision, session common.Hash, verify, checkPublication func(context.Context) error) error {
	a := body.Authorization
	now := time.Now()
	// Keep the monotonic clock reading while using whole seconds in the signed certificate.
	issued := now.Add(-time.Duration(now.Nanosecond()))
	deadline := issued.Add(time.Duration(a.Seconds) * time.Second)
	record := leaseRecord{ID: session, Issued: issued.Unix(), Deadline: deadline.Unix(), State: lease.Reserved}
	accepted, err := h.Journal.decide(a.RequestID, manifest, decision, Authorized, nil, &record)
	if err != nil || !accepted {
		return err
	}
	id := hex.EncodeToString(session[:])
	provisionErr := h.Journal.updateLease(a.RequestID, lease.Provisioning, nil)
	if provisionErr == nil {
		call, cancel := context.WithDeadline(ctx, deadline)
		provisionErr = h.issue(call, body, record, manifest, decision, lease.Grant{
			ID: id, Role: a.Role, Deadline: deadline, WireGuard: body.WireGuard, SSH: body.SSH, Recheck: verify,
		}, checkPublication)
		cancel()
	}
	if provisionErr == nil {
		return nil
	}
	// The approval stays consumed even when the host or delivery fails.
	recovery, stop := context.WithTimeout(context.Background(), 18*time.Second)
	defer stop()
	cleanup := h.SSH.Close(recovery, id)
	observedID, observed, observationErr := h.SSH.Observe(recovery)
	state := lease.Closed
	if cleanup != nil || observationErr != nil || (observedID == id && observed != lease.Closed) {
		state = lease.CleanupIncomplete
	}
	h.progress(session, fmt.Sprintf("%s · %v", ProvisionFailed, provisionErr))
	notice, err := h.notice(a, body, ProvisionFailed, manifest, decision, session, nil)
	if err != nil {
		return errors.Join(provisionErr, cleanup, err)
	}
	if err := h.Journal.updateLease(a.RequestID, state, &notice); err != nil {
		return errors.Join(provisionErr, cleanup, err)
	}
	h.progress(session, string(state))
	return nil
}

func (h Host) issue(ctx context.Context, body doorPayload, record leaseRecord, manifest, decision common.Hash, grant lease.Grant, checkPublication func(context.Context) error) error {
	conn, err := h.SSH.Provision(ctx, grant)
	if err != nil {
		return err
	}
	defer clear(conn.PSK[:])
	a := body.Authorization
	private := connection{Issued: record.Issued, Deadline: record.Deadline, ClientWireGuard: body.WireGuard, Data: conn}
	defer clear(private.Data.PSK[:])
	notice, err := h.notice(a, body, Ready, manifest, decision, record.ID, &private)
	if err != nil {
		return err
	}
	if err := h.Journal.updateLease(a.RequestID, lease.Ready, &notice); err != nil {
		return err
	}
	h.progress(record.ID, fmt.Sprintf("Ready. Expires %s UTC", grant.Deadline.UTC().Format("15:04:05")))
	if err := checkPublication(ctx); err != nil {
		return fmt.Errorf("recheck before publishing access: %w", err)
	}
	if err := h.publish(ctx, notice); err != nil {
		// A lost acknowledgment can be retried with identical ciphertext.
		if err := checkPublication(ctx); err != nil {
			return fmt.Errorf("recheck before retrying the connection reply: %w", err)
		}
		if err := h.publish(ctx, notice); err != nil {
			return err
		}
	}
	return h.Journal.delivered(a.RequestID, notice.ID)
}

func (h Host) progress(id common.Hash, stage string) {
	if h.Progress != nil {
		h.Progress(fmt.Sprintf("Session %s · %s", id.Hex(), stage))
	}
}

func (h Host) MonitorSSH(ctx context.Context) error {
	ticker := time.NewTicker(600 * time.Millisecond)
	defer ticker.Stop()
	for {
		id, state, err := h.SSH.Observe(ctx)
		if err != nil {
			return err
		}
		if id != "" && state != lease.Provisioning && state != lease.Ready {
			session := common.HexToHash(id)
			changed, err := h.Journal.observeLease(session, state)
			if err != nil {
				return err
			}
			if changed {
				h.progress(session, string(state))
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
