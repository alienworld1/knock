package main

import (
	"testing"
	"time"

	"knock/internal/admission"
	"knock/internal/lease"
)

func TestSessionDisplayUsesVerifiedLifecycleEvidence(t *testing.T) {
	now := time.Now()
	record := admission.SessionStatus{
		State: lease.Active, Observed: now.Unix(), Deadline: now.Add(time.Minute).Unix(),
		ChainAt: now.Unix(), Degraded: true,
	}
	if shown := displaySession(now, &record, false); shown.State != string(lease.Active) || shown.Monitoring != "Degraded" {
		t.Fatalf("access and monitoring states were conflated: %+v", shown)
	}
	for _, observation := range []sessionDisplay{
		displaySession(now, &record, true),
		displaySession(now.Add(time.Minute), &record, false),
	} {
		if observation.State != "Unknown" || observation.LastVerified.State != lease.Active {
			t.Fatalf("missing fresh evidence implied closure or live access: %+v", observation)
		}
	}
	record.State = lease.Closed
	record.ClosedAt = now.Unix()
	if shown := displaySession(now.Add(time.Minute), &record, true); shown.State != string(lease.Closed) {
		t.Fatalf("discarded valid terminal host evidence: %+v", shown)
	}
}
