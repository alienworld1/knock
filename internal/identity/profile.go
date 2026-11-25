package identity

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"filippo.io/age"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	qoreseal "github.com/qorechain/qoreseal/go"
	qoresign "github.com/qorechain/qoresign/go"
)

const profileHeader = "knock identity v1\n"
const secretLength = 32

type Keys struct {
	Account   qoresign.AccountAddress
	Classical qoresign.ClassicalKey
	Signing   qoresign.PqKeyPair
	Recipient qoreseal.SealKeyPair
}

func (k *Keys) Clear() {
	clear(k.Classical.PrivateKey)
	clear(k.Signing.SecretKey)
	clear(k.Recipient.Seed)
	clear(k.Recipient.MlkemSecretKey)
	clear(k.Recipient.X25519SecretKey)
}

func Init(path string, passphrase []byte) (qoresign.AccountAddress, error) {
	var empty qoresign.AccountAddress
	if len(passphrase) == 0 {
		return empty, errors.New("enter a profile passphrase")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return empty, err
	}
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return empty, err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return empty, errors.New("the profile directory must have permissions 0700")
	}
	private, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return empty, err
	}
	defer private.Zero()
	secret := make([]byte, 3*secretLength)
	defer clear(secret)
	serialized := private.Serialize()
	copy(secret, serialized)
	clear(serialized)
	rand.Read(secret[secretLength:])
	account, err := qoresign.AddressFromPublicKey(private.PubKey().SerializeCompressed(), qoresign.EthSecp256k1)
	if err != nil {
		return empty, err
	}

	recipient, err := age.NewScryptRecipient(string(passphrase))
	if err != nil {
		return empty, err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".identity-*")
	if err != nil {
		return empty, err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	encrypted, err := age.Encrypt(file, recipient)
	if err != nil {
		return empty, err
	}
	if _, err := io.WriteString(encrypted, profileHeader); err != nil {
		return empty, err
	}
	if _, err := encrypted.Write(secret); err != nil {
		return empty, err
	}
	if err := encrypted.Close(); err != nil {
		return empty, err
	}
	if err := file.Sync(); err != nil {
		return empty, err
	}
	if err := file.Close(); err != nil {
		return empty, err
	}
	if err := os.Link(file.Name(), path); err != nil {
		return empty, fmt.Errorf("save identity profile: %w", err)
	}
	return account, nil
}

func Unlock(path string, passphrase []byte) (*Keys, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open identity", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 8192 {
		return nil, errors.New("expected a small encrypted identity file with permissions 0600")
	}

	identity, err := age.NewScryptIdentity(string(passphrase))
	if err != nil {
		return nil, err
	}
	// Accept the work factor written by the pinned age release and limit untrusted input.
	identity.SetMaxWorkFactor(18)
	plaintext, err := age.Decrypt(file, identity)
	if err != nil {
		return nil, errors.New("couldn't unlock identity profile")
	}
	const size = len(profileHeader) + 3*secretLength
	data, err := io.ReadAll(io.LimitReader(plaintext, int64(size+1)))
	defer clear(data)
	if err != nil || len(data) != size || !bytes.HasPrefix(data, []byte(profileHeader)) {
		return nil, errors.New("invalid encrypted identity profile")
	}

	secret := data[len(profileHeader):]
	result := new(Keys)
	result.Classical, err = qoresign.ClassicalKeyFromPrivate(secret[:secretLength], qoresign.EthSecp256k1)
	if err == nil {
		result.Account, err = qoresign.AddressFromPublicKey(result.Classical.PublicKey, result.Classical.Type)
	}
	if err == nil {
		result.Signing, err = qoresign.PqKeyFromSeed(secret[secretLength : 2*secretLength])
	}
	if err == nil {
		result.Recipient, err = qoreseal.SealKeysFromSeed(secret[2*secretLength:])
	}
	if err != nil {
		result.Clear()
		return nil, errors.New("invalid identity keys")
	}
	return result, nil
}
