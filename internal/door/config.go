package door

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"knock/internal/chain"
	"knock/internal/lease"
	"knock/internal/protocol"

	"github.com/ethereum/go-ethereum/common"
)

type Config struct {
	Registry          chain.Registry `json:"registry"`
	DoorID            common.Hash    `json:"doorId"`
	Owner             string         `json:"owner"`
	Account           string         `json:"account"`
	OwnerProfile      string         `json:"ownerProfile"`
	DoorProfile       string         `json:"doorProfile"`
	Cards             string         `json:"cards"`
	Mailbox           string         `json:"mailbox,omitempty"`
	State             string         `json:"state,omitempty"`
	WireGuardEndpoint string         `json:"wireGuardEndpoint,omitempty"`
	Policy            Policy         `json:"policy"`
}

func ReadConfig(path string, output any) error {
	data, err := readBounded(path, 16<<10)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	if decoder.Decode(new(json.RawMessage)) != io.EOF {
		return errors.New("unexpected data after configuration")
	}
	return nil
}

func LoadConfig(path string) (Config, error) {
	var config Config
	if err := ReadConfig(path, &config); err != nil {
		return config, err
	}
	if config.Registry.Address == (common.Address{}) || config.Registry.CodeHash == (common.Hash{}) ||
		config.DoorID == (common.Hash{}) || config.DoorProfile == "" || config.Cards == "" || config.Owner == config.Account {
		return config, errors.New("configuration requires a registry, Door ID, distinct owner and Door accounts, Door profile, and Card directory")
	}
	if _, err := ParseAccount(config.Owner); err != nil {
		return config, fmt.Errorf("owner: %w", err)
	}
	if _, err := ParseAccount(config.Account); err != nil {
		return config, fmt.Errorf("Door: %w", err)
	}
	if config.Mailbox != "" {
		if _, err := protocol.Origin(config.Mailbox); err != nil {
			return config, err
		}
	}
	if config.WireGuardEndpoint != "" {
		if _, err := lease.ValidateEndpoint(config.WireGuardEndpoint); err != nil {
			return config, err
		}
		if config.Mailbox == "" || config.State == "" {
			return config, errors.New("SSH access requires a Mailbox and a Door admission state file")
		}
	}
	if _, err := config.Policy.ChainPolicy(); err != nil {
		return config, err
	}
	for _, value := range []*string{&config.OwnerProfile, &config.DoorProfile, &config.Cards, &config.State} {
		if *value != "" && !filepath.IsAbs(*value) {
			*value = filepath.Join(filepath.Dir(path), *value)
		}
	}
	return config, nil
}

func ReadCard(directory, account string) (Card, error) {
	if _, err := ParseAccount(account); err != nil {
		return Card{}, err
	}
	data, err := readBounded(filepath.Join(directory, account+".card"), MaxCardSize)
	if err != nil {
		return Card{}, err
	}
	return Decode(data)
}

func WriteCard(directory string, card Card) error {
	if _, err := ParseAccount(card.Details.Account); err != nil {
		return err
	}
	payload, err := card.Encode()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(directory, 0755); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".card-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.Write(payload); err != nil {
		return err
	}
	if err := file.Chmod(0644); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), filepath.Join(directory, card.Details.Account+".card"))
}

type Alias struct {
	Account    string      `json:"account"`
	SigningKey common.Hash `json:"signingKey"`
}

func SaveAlias(directory, name string, alias Alias) error {
	if !IsAlias(name) {
		return errors.New("alias must use lowercase letters, numbers, or hyphens")
	}
	if err := privateAliasDirectory(directory, true); err != nil {
		return err
	}
	path := filepath.Join(directory, name)
	file, err := os.CreateTemp(directory, ".alias-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := json.NewEncoder(file).Encode(alias); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	err = os.Link(file.Name(), path)
	if errors.Is(err, os.ErrExist) {
		current, readErr := ReadAlias(directory, name)
		if readErr == nil && current == alias {
			return nil
		}
		return errors.New("alias already names an identity. Choose a new alias.")
	}
	return err
}

func ReadAlias(directory, name string) (Alias, error) {
	if !IsAlias(name) {
		return Alias{}, errors.New("invalid Door alias")
	}
	if err := privateAliasDirectory(directory, false); err != nil {
		return Alias{}, err
	}
	path := filepath.Join(directory, name)
	info, err := os.Lstat(path)
	if err != nil {
		return Alias{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return Alias{}, errors.New("alias must be a private regular file")
	}
	var alias Alias
	if err := ReadConfig(path, &alias); err != nil {
		return Alias{}, err
	}
	return alias, nil
}

func privateAliasDirectory(directory string, create bool) error {
	if create {
		if err := os.MkdirAll(directory, 0700); err != nil {
			return err
		}
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("alias directory must have permissions 0700")
	}
	return nil
}

func readBounded(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maximum {
		return nil, errors.New("expected a small regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err == nil && int64(len(data)) > maximum {
		return nil, errors.New("file exceeds the size limit")
	}
	return data, err
}
