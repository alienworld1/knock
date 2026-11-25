package protocol

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

// OpenState keeps account and Door state in a private, single-writer directory.
func OpenState(path string) (*bolt.DB, error) {
	if path == "" {
		return nil, errors.New("set a state file path")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, errors.New("state directory must have permissions 0700")
	}
	info, err = os.Lstat(path)
	switch {
	case err == nil && (!info.Mode().IsRegular() || info.Mode().Perm() != 0600):
		return nil, errors.New("state file must be regular with permissions 0600")
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return nil, err
	}
	return bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
}
