package door

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"knock/internal/chain"
	"knock/internal/identity"

	"github.com/ethereum/go-ethereum/common"
	qoreseal "github.com/qorechain/qoreseal/go"
)

func Register(ctx context.Context, config Config, operator, keys *identity.Keys, report func(string)) error {
	if keys.Account.Bech32 != config.Account || operator.Account.Bech32 != config.Owner {
		return errors.New("local identity profiles do not control the configured owner and Door accounts")
	}
	native := chain.Diana()
	evm, err := chain.Connect(ctx, native)
	if err != nil {
		return err
	}
	defer evm.Close()
	state, block, err := evm.Door(ctx, config.Registry, config.DoorID)
	if err != nil {
		return err
	}
	for _, approver := range config.Policy.Approvers {
		account, err := ParseAccount(approver)
		if err != nil {
			return err
		}
		signing, err := native.SigningKey(ctx, approver)
		if err != nil {
			return fmt.Errorf("approver %s: %w", approver, err)
		}
		if err := evm.Binding(ctx, account, signing, block); err != nil {
			return err
		}
	}
	recipient, err := recipientCard(ctx, native, keys)
	if err != nil {
		return err
	}
	policy, err := config.Policy.ChainPolicy()
	if err != nil {
		return err
	}

	switch {
	case state.Version == 0 && config.Policy.Version == 1:
		err = evm.RegisterDoor(ctx, config.Registry, config.DoorID, policy, operator, keys, report)
	case state.Version == 0:
		return errors.New("a new Door starts at policy version 1")
	case state.Owner != common.BytesToAddress(operator.Account.Bytes) || state.Account != common.BytesToAddress(keys.Account.Bytes):
		return errors.New("registry has a different owner or Door account")
	case config.Policy.Version == state.Version+1:
		err = evm.UpdatePolicy(ctx, config.Registry, config.DoorID, config.Policy.Version, policy, operator, report)
	case state.Version != config.Policy.Version || !matchesPolicy(state.Policy, policy):
		return errors.New("use the next policy version to change the registered policy")
	}
	if err != nil {
		return err
	}
	if config.Policy.Offer != nil && config.Policy.Enabled {
		offer, err := config.Policy.PaymentOffer()
		if err != nil {
			return err
		}
		if err := evm.SetOffer(ctx, config.Registry, config.DoorID, offer, operator, report); err != nil {
			return err
		}
	}
	card, err := NewCard(config, operator.Account.Bech32, keys, recipient, time.Now())
	if err != nil {
		return err
	}
	if err := card.Verify(ctx, native, evm, config.Registry, config.Account); err != nil {
		return err
	}
	return WriteCard(config.Cards, card)
}

func recipientCard(ctx context.Context, native *chain.Native, keys *identity.Keys) (qoreseal.RecipientCard, error) {
	card, err := qoreseal.SignRecipientCard(qoreseal.SignRecipientCardArgs{
		ChainID: chain.NativeID, Address: keys.Account.Bech32, Keys: keys.Recipient,
		ClassicalKey: keys.Classical, PqKey: keys.Signing,
	})
	if err != nil {
		return card, err
	}
	_, err = native.Recipient(ctx, card, keys.Account.Bech32)
	return card, err
}

func Serve(ctx context.Context, config Config, keys *identity.Keys, report func(string)) error {
	if keys.Account.Bech32 != config.Account {
		return errors.New("local profile does not control the configured Door account")
	}
	native := chain.Diana()
	evm, err := chain.Connect(ctx, native)
	if err != nil {
		return err
	}
	defer evm.Close()
	signing := sha256.Sum256(keys.Signing.PublicKey)
	kem := sha256.Sum256(keys.Recipient.MlkemPublicKey)
	keys.Clear()
	policy, err := config.Policy.ChainPolicy()
	if err != nil {
		return err
	}
	check := func() error {
		call, cancel := context.WithTimeout(ctx, 24*time.Second)
		defer cancel()
		card, err := ReadCard(config.Cards, config.Account)
		if err != nil {
			return err
		}
		d := card.Details
		if d.DoorID != config.DoorID || d.Owner != config.Owner || d.SigningKey != signing || d.KEMKey != kem ||
			d.PolicyCommitment != policy.Commitment {
			return errors.New("Door Card does not match the local configuration and keys")
		}
		return card.Verify(call, native, evm, config.Registry, config.Account)
	}
	if err := check(); err != nil {
		return err
	}
	report("Door verified and closed")
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := check(); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("Door verification stopped: %w", err)
			}
		}
	}
}
