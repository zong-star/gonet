// Package secretfile stores console-managed SNMP credentials outside public
// configuration and API state. Windows blobs are protected for the current user.
package secretfile

import (
	"errors"
	"os"
	"path/filepath"
)

func Read(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16384 {
		return "", errors.New("SNMP credential file is unavailable")
	}
	if err = checkMode(info); err != nil {
		return "", err
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		return "", errors.New("SNMP credential file is unavailable")
	}
	plain, err := unprotect(blob)
	if err != nil || len(plain) == 0 {
		return "", errors.New("SNMP credential file cannot be opened")
	}
	return string(plain), nil
}

// Store returns an in-memory rollback operation; it creates no backup files.
func Store(path, value string) (func() error, error) {
	old, err := os.ReadFile(path)
	existed := err == nil
	if err != nil && !os.IsNotExist(err) {
		return nil, errors.New("SNMP credential file cannot be updated")
	}
	blob, err := protect([]byte(value))
	if err != nil {
		return nil, errors.New("SNMP credential cannot be protected")
	}
	if err = write(path, blob); err != nil {
		return nil, errors.New("SNMP credential file cannot be updated")
	}
	return func() error {
		if existed {
			return write(path, old)
		}
		return os.Remove(path)
	}, nil
}

func write(path string, blob []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".snmp-secret-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(blob)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(tmp, path)
}
