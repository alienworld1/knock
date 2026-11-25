package identity

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestProfileEncryptedRoundTrip(t *testing.T) {
	file := filepath.Join(t.TempDir(), "identity", "profile.age")
	password := []byte("M1 test passphrase")
	address, err := Init(file, password)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Init(file, []byte("different")); err == nil {
		t.Fatal("overwrote existing profile")
	}
	after, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("existing encrypted profile changed")
	}
	if _, err := Unlock(file, []byte("incorrect")); err == nil {
		t.Fatal("wrong password unlocked profile")
	}
	keys, err := Unlock(file, password)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Clear()
	if keys.Account.Bech32 != address.Bech32 || bytes.Contains(before, keys.Classical.PrivateKey) ||
		bytes.Contains(before, keys.Recipient.Seed) || bytes.Contains(before, keys.Signing.SecretKey) {
		t.Fatal("profile identity changed or exposed keys")
	}
	if err := os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Unlock(file, password); err == nil {
		t.Fatal("opened a non-private profile")
	}
}
