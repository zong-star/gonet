//go:build !windows

package secretfile

import (
	"bytes"
	"errors"
	"os"
)

var header = []byte("GONET-PRIVATE-1\n")

func protect(data []byte) ([]byte, error) {
	return append(append([]byte(nil), header...), data...), nil
}

func unprotect(blob []byte) ([]byte, error) {
	if !bytes.HasPrefix(blob, header) {
		return nil, errors.New("unsupported credential format")
	}
	return append([]byte(nil), blob[len(header):]...), nil
}

func checkMode(info os.FileInfo) error {
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("SNMP credential file must have private permissions")
	}
	return nil
}
