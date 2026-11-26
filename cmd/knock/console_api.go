package main

import (
	"cmp"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"knock/internal/admission"
	"knock/internal/chain"
	"knock/internal/door"
	"knock/internal/identity"
	"knock/internal/lease"
	"knock/internal/mailbox"
	"knock/internal/protocol"

	"github.com/ethereum/go-ethereum/common"
)

type operatorConsole struct {
	settings *settings
	keys     *identity.Keys
	// Serialize local mutations. Track unresolved chain submissions so an
	// interrupted browser request cannot cause an automatic second transaction.
	mutations   sync.Mutex
	revocations sync.Map             // session reference -> "Checking registry" or "Registry revocation confirmed"
	rotations   map[string]time.Time // accessed under mutations
}

func (c *operatorConsole) routes() http.Handler {
	api := http.NewServeMux()
	api.HandleFunc("GET /api/doors", c.listDoors)
	api.HandleFunc("GET /api/door", c.inspectDoor)
	api.HandleFunc("GET /api/requests", c.requests)
	api.HandleFunc("GET /api/request", c.requests)
	api.HandleFunc("POST /api/decision", c.decision)
	api.HandleFunc("GET /api/sessions", c.sessions)
	api.HandleFunc("POST /api/revoke", c.revoke)
	api.HandleFunc("GET /api/history", c.history)
	api.HandleFunc("POST /api/rotation", c.rotate)
	return api
}

type localConsoleDoor struct {
	Target  string `json:"target"`
	Account string `json:"account"`
	Alias   string `json:"alias,omitempty"`
}

func (c *operatorConsole) listDoors(w http.ResponseWriter, _ *http.Request) {
	directory := c.settings.cardsDirectory()
	files, err := os.ReadDir(directory)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		consoleError(w, 503, "Couldn't read Door Cards. Check the configured cards directory.")
		return
	}
	aliases := make(map[string]string)
	if c.settings.home != "" {
		dir := filepath.Join(c.settings.home, "aliases")
		names, err := os.ReadDir(dir)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			consoleError(w, 503, "Couldn't read Door aliases. Check the local configuration.")
			return
		}
		for _, name := range names {
			if record, err := door.ReadAlias(dir, name.Name()); err == nil && aliases[record.Account] == "" {
				aliases[record.Account] = name.Name()
			}
		}
	}
	doors := make([]localConsoleDoor, 0, len(files))
	for _, file := range files {
		account, ok := strings.CutSuffix(file.Name(), ".card")
		if !ok || !file.Type().IsRegular() {
			continue
		}
		if _, err := door.ParseAccount(account); err != nil {
			continue
		}
		entry := localConsoleDoor{Target: account, Account: account, Alias: aliases[account]}
		if entry.Alias != "" {
			entry.Target = entry.Alias
		}
		doors = append(doors, entry)
	}
	consoleJSON(w, 200, struct {
		Doors    []localConsoleDoor `json:"doors"`
		Identity string             `json:"identity"`
	}{doors, c.keys.Account.Bech32})
}

func (c *operatorConsole) inspectDoor(w http.ResponseWriter, r *http.Request) {
	err := c.settings.withVerifiedDoor(r.Context(), r.URL.Query().Get("door"), func(_ context.Context, _ *chain.EVM, card door.Card) error {
		d := card.Details
		account := c.keys.Account.Bech32
		var service, price, beneficiary string
		if offer := d.Policy.Offer; offer != nil {
			service, price, beneficiary = offer.Service, formatQOR(offer.PriceUQOR), offer.Beneficiary
		}
		consoleJSON(w, 200, struct {
			Mode               string         `json:"mode"`
			Enabled            bool           `json:"enabled"`
			PolicyVersion      string         `json:"policyVersion"`
			Limit              uint64         `json:"limit"`
			Roles              []string       `json:"roles"`
			Approvers          []string       `json:"approvers,omitempty"`
			ApproversCanRevoke bool           `json:"approversCanRevoke"`
			Service            string         `json:"service,omitempty"`
			Price              string         `json:"price,omitempty"`
			Beneficiary        string         `json:"beneficiary,omitempty"`
			CanReview          bool           `json:"canReview"`
			CanRevoke          bool           `json:"canRevoke"`
			CanRotate          bool           `json:"canRotate"`
			Owner              string         `json:"owner"`
			SigningKey         common.Hash    `json:"signingKey"`
			Registry           common.Address `json:"registry"`
			CardExpires        int64          `json:"cardExpires"`
		}{
			Mode: d.Mode, Enabled: d.Policy.Enabled, PolicyVersion: strconv.FormatUint(d.Policy.Version, 10),
			Limit: d.Policy.MaxDurationSeconds, Roles: d.Policy.Roles,
			Approvers: d.Policy.Approvers, ApproversCanRevoke: d.Policy.ApproversCanRevoke,
			Service: service, Price: price, Beneficiary: beneficiary,
			CanReview: d.Policy.Enabled && slices.Contains(d.Policy.Approvers, account),
			CanRevoke: d.Policy.Enabled && canRevoke(card, account),
			CanRotate: d.Policy.Enabled && d.Owner == account, Owner: d.Owner,
			SigningKey: d.SigningKey, Registry: d.Registry.Address, CardExpires: d.Expires,
		})
		return nil
	})
	if err != nil {
		consoleError(w, 503, "Couldn't verify the Door Card and current policy. Check the Card and try again.")
	}
}

type consoleReview struct {
	admission.ReviewSummary
	Reason    string `json:"reason,omitempty"`
	Decision  string `json:"decision,omitempty"`
	Delivered bool   `json:"delivered"`
}

func (c *operatorConsole) requests(w http.ResponseWriter, r *http.Request) {
	var id common.Hash
	if r.URL.Path == "/api/request" {
		var err error
		id, err = requestTarget([]string{r.URL.Query().Get("id")})
		if err != nil {
			consoleError(w, 400, "Invalid request reference.")
			return
		}
	}
	target := r.URL.Query().Get("door")
	items := make([]consoleReview, 0)
	err := c.withDoorReviews(r.Context(), target, id, func(_ context.Context, _ admission.Diana, _ *mailbox.Client, _ *identity.Keys, reviews []admission.Review) error {
		if len(reviews) == 0 {
			return nil
		}
		db, err := protocol.OpenState(c.settings.operatorState(c.keys))
		if err != nil {
			return err
		}
		defer db.Close()
		for _, review := range reviews {
			item := consoleReview{ReviewSummary: review.Summary()}
			outcome, delivered, err := admission.DecisionProgress(db, item.ID)
			if err != nil {
				return err
			}
			item.Delivered = delivered
			switch outcome {
			case admission.Authorized:
				item.Decision = "approve"
			case admission.Denied:
				item.Decision = "deny"
			}
			if id != (common.Hash{}) {
				item.Reason = review.Reason()
			}
			items = append(items, item)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, errOperatorUnauthorized) {
			consoleError(w, 403, "This identity can't review requests for this Door.")
		} else if id != (common.Hash{}) {
			consoleError(w, 503, "Can't verify this request. It may have expired. Refresh the request list.")
		} else {
			consoleError(w, 503, "Couldn't verify request updates. Check Diana and the Door's Mailbox.")
		}
		return
	}
	consoleJSON(w, 200, items)
}

func (c *operatorConsole) withDoorReviews(ctx context.Context, target string, id common.Hash,
	use func(context.Context, admission.Diana, *mailbox.Client, *identity.Keys, []admission.Review) error,
) error {
	return c.settings.withVerifiedDoor(ctx, target, func(ctx context.Context, _ *chain.EVM, card door.Card) error {
		d := card.Details
		if !d.Policy.Enabled || !slices.Contains(d.Policy.Approvers, c.keys.Account.Bech32) {
			return errOperatorUnauthorized
		}
		if c.settings.mailbox != "" && c.settings.mailbox != d.Mailbox {
			return errors.New("configured Mailbox differs from the signed Door Card")
		}
		perDoor := *c.settings
		perDoor.mailbox = d.Mailbox
		return perDoor.loadReviews(ctx, id, c.keys, func(ctx context.Context, authority admission.Diana, relay *mailbox.Client, keys *identity.Keys, reviews []admission.Review) error {
			reviews = slices.DeleteFunc(reviews, func(review admission.Review) bool { return review.Summary().Door != d.Account })
			if id != (common.Hash{}) && len(reviews) != 1 {
				return admission.ErrInvalid
			}
			return use(ctx, authority, relay, keys, reviews)
		})
	})
}

func (c *operatorConsole) beginMutation(w http.ResponseWriter) bool {
	if c.mutations.TryLock() {
		return true
	}
	consoleError(w, 409, "Another action is in progress. Wait for its result.")
	return false
}

func (c *operatorConsole) decision(w http.ResponseWriter, r *http.Request) {
	var input struct{ Door, ID, Decision string }
	if !consoleBody(w, r, &input) {
		return
	}
	id, err := requestTarget([]string{input.ID})
	outcome := admission.Authorized
	if input.Decision == "deny" {
		outcome = admission.Denied
	}
	if err != nil || (input.Decision != "approve" && input.Decision != "deny") {
		consoleError(w, 400, "Select a request and decision.")
		return
	}
	if !c.beginMutation(w) {
		return
	}
	defer c.mutations.Unlock()
	err = c.withDoorReviews(r.Context(), input.Door, id, func(ctx context.Context, authority admission.Diana, relay *mailbox.Client, keys *identity.Keys, reviews []admission.Review) error {
		return c.settings.sendDecision(ctx, authority, relay, keys, reviews[0], outcome)
	})
	switch {
	case errors.Is(err, errOperatorUnauthorized):
		consoleError(w, 403, "This identity can't decide requests for this Door.")
	case err != nil:
		consoleError(w, 409, "Couldn't confirm decision delivery. Refresh the request before continuing.")
	default:
		consoleJSON(w, 200, map[string]string{"message": "Decision sent. Waiting for the Door to verify it."})
	}
}

type consoleSession struct {
	sessionDisplay
	Revocation string `json:"revocation,omitempty"`
	Revocable  bool   `json:"revocable"`
}

func (c *operatorConsole) sessions(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("door")
	records, loadErr := c.settings.loadSessionStatus(r.Context(), target, c.keys)
	var revocable bool
	var reconciling bool
	for _, record := range records {
		_, waiting := c.revocations.Load(record.Session)
		reconciling = reconciling || (waiting && record.RevokedAt == 0 && record.State != lease.Closed)
	}
	// Check current policy before exposing the action. Host evidence remains
	// visible through an outage, including durable closure observations.
	policyCtx, cancelPolicy := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancelPolicy()
	err := c.settings.withVerifiedDoor(policyCtx, target, func(ctx context.Context, evm *chain.EVM, card door.Card) error {
		revocable = canRevoke(card, c.keys.Account.Bech32)
		if reconciling {
			for _, item := range records {
				if state, _ := c.revocations.Load(item.Session); state == "Checking registry" && item.DoorID == card.Details.DoorID && item.RevokedAt == 0 && item.State != lease.Closed {
					if confirmed, err := evm.Revoked(ctx, card.Details.Registry, card.Details.DoorID, item.Session); err == nil && confirmed {
						c.revocations.Store(item.Session, "Registry revocation confirmed")
					}
				}
			}
		}
		return nil
	})
	items := make([]consoleSession, 0, len(records))
	now := time.Now()
	sessionRank := func(record admission.SessionStatus) int {
		switch record.State {
		case lease.CleanupIncomplete:
			return 0
		case lease.Closed:
			return 2
		default:
			return 1
		}
	}
	slices.SortFunc(records, func(a, b admission.SessionStatus) int {
		if rank := cmp.Compare(sessionRank(a), sessionRank(b)); rank != 0 {
			return rank
		}
		if obs := cmp.Compare(b.Observed, a.Observed); obs != 0 {
			return obs
		}
		return strings.Compare(a.Session.Hex(), b.Session.Hex())
	})
	for _, record := range records {
		display := displaySession(now, &record, loadErr != nil)
		progress, _ := c.revocations.Load(record.Session)
		revokeState, _ := progress.(string)
		if record.RevokedAt != 0 {
			if record.ClosedAt != 0 && record.Cause == "Revoked" {
				revokeState = "Enforced by the Door"
			} else {
				revokeState = "Revocation observed by the Door"
			}
		}
		items = append(items, consoleSession{display, revokeState, err == nil && revocable && revokeState == "" &&
			(display.State == string(lease.Ready) || display.State == string(lease.Active))})
	}
	message := ""
	if loadErr != nil {
		message = "Session updates unavailable. Check Diana and the Door's Mailbox."
	} else if err != nil {
		message = "Current Door policy is unavailable. Revocation is disabled until verification returns."
	}
	consoleJSON(w, 200, struct {
		Sessions []consoleSession `json:"sessions"`
		Warning  string           `json:"warning,omitempty"`
	}{items, message})
}

func (c *operatorConsole) revoke(w http.ResponseWriter, r *http.Request) {
	var input struct{ Door, ID string }
	if !consoleBody(w, r, &input) {
		return
	}
	id, err := requestTarget([]string{input.ID})
	if err != nil {
		consoleError(w, 400, "Invalid session reference.")
		return
	}
	if !c.beginMutation(w) {
		return
	}
	defer c.mutations.Unlock()
	if _, waiting := c.revocations.Load(id); waiting {
		consoleError(w, 409, "Revocation is already being tracked. Check session updates.")
		return
	}
	var attempted bool
	err = c.settings.withVerifiedDoor(r.Context(), input.Door, func(ctx context.Context, evm *chain.EVM, card door.Card) error {
		if !canRevoke(card, c.keys.Account.Bech32) {
			return errOperatorUnauthorized
		}
		records, err := c.settings.readSessionEvidence(ctx, card, c.keys, nil)
		if err != nil || !slices.ContainsFunc(records, func(record admission.SessionStatus) bool {
			return record.Session == id && record.Fresh(time.Now()) && record.RevokedAt == 0 &&
				(record.State == lease.Ready || record.State == lease.Active)
		}) {
			return errors.New("could not verify a ready or active session")
		}
		attempted = true
		return revokeVerified(ctx, evm, card, id, c.keys, func(progress string) {
			if strings.HasPrefix(progress, "EVM transaction submitted ") {
				c.revocations.Store(id, "Checking registry")
			}
		})
	})
	switch {
	case errors.Is(err, errOperatorUnauthorized):
		consoleError(w, 403, "This identity can't revoke access for this Door.")
	case err != nil && !attempted:
		consoleError(w, 409, "Couldn't verify that this session is ready or active. Refresh its status.")
	case err != nil:
		// A failed broadcast can still have reached a node. Require
		// reconciliation instead of providing a blind retry.
		c.revocations.LoadOrStore(id, "Checking registry")
		consoleError(w, 409, "Couldn't confirm revocation. Check the registry and wait for signed Door status.")
	default:
		c.revocations.Store(id, "Registry revocation confirmed")
		consoleJSON(w, 200, map[string]string{"message": "Registry revocation confirmed. Waiting for the Door to verify closure."})
	}
}

func (c *operatorConsole) history(w http.ResponseWriter, r *http.Request) {
	receipts, err := c.settings.loadHistory(r.Context(), r.URL.Query().Get("door"), "", c.keys)
	if receipts == nil {
		receipts = []admission.AuditReceipt{}
	}
	message := ""
	if err != nil {
		message = "Receipt updates unavailable. Check Diana and the Door's Mailbox."
	}
	consoleJSON(w, 200, struct {
		Receipts []admission.AuditReceipt `json:"receipts"`
		Warning  string                   `json:"warning,omitempty"`
	}{receipts, message})
}

func (c *operatorConsole) rotate(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Door, Epoch string
		Members     []string
		Clear       bool
	}
	if !consoleBody(w, r, &input) {
		return
	}
	epoch, err := strconv.ParseUint(input.Epoch, 10, 64)
	if err != nil || epoch == ^uint64(0) || input.Clear != (len(input.Members) == 0) || len(input.Members) > 16 {
		consoleError(w, 400, "Enter the current epoch and up to 16 distinct Diana accounts, or choose Remove all auditors.")
		return
	}
	accounts := slices.Clone(input.Members)
	slices.Sort(accounts)
	for n, account := range accounts {
		if _, err := door.ParseAccount(account); err != nil || n > 0 && account == accounts[n-1] {
			consoleError(w, 400, "Enter distinct Diana accounts.")
			return
		}
	}
	if !c.beginMutation(w) {
		return
	}
	defer c.mutations.Unlock()
	card, _, _, err := c.settings.localDoor(input.Door)
	if err != nil {
		consoleError(w, 400, "Select a configured Door.")
		return
	}
	rotation := card.Details.DoorID.Hex() + "/" + strconv.FormatUint(epoch, 10)
	now := time.Now()
	for id, deadline := range c.rotations {
		if !now.Before(deadline) {
			delete(c.rotations, id)
		}
	}
	if now.Before(c.rotations[rotation]) {
		consoleError(w, 409, "A rotation was recently requested. Check the epoch in the Door log before sending another.")
		return
	}
	err = c.settings.rotateAudit(r.Context(), input.Door, c.keys, epoch, accounts)
	if errors.Is(err, errOperatorUnauthorized) {
		consoleError(w, 403, "Only this Door's owner can request audit rotation.")
		return
	}
	if c.rotations == nil {
		c.rotations = make(map[string]time.Time)
	}
	c.rotations[rotation] = time.Now().Add(5 * time.Minute)
	if err != nil {
		consoleError(w, 409, "Couldn't confirm rotation delivery. Check the Door log before sending another.")
		return
	}
	consoleJSON(w, 200, map[string]string{"message": "Rotation requested. Check the Door log for the committed epoch."})
}
