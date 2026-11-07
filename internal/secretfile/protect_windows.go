package secretfile

import (
	"bytes"
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var header = []byte("GONET-DPAPI-1\n")

func transform(data []byte, decrypt bool) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty credential")
	}
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out windows.DataBlob
	var err error
	if decrypt {
		err = windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	} else {
		err = windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	}
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, int(out.Size))...), nil
}

func protect(data []byte) ([]byte, error) {
	blob, err := transform(data, false)
	return append(append([]byte(nil), header...), blob...), err
}

func unprotect(blob []byte) ([]byte, error) {
	if !bytes.HasPrefix(blob, header) {
		return nil, errors.New("unsupported credential format")
	}
	return transform(blob[len(header):], true)
}

func checkMode(os.FileInfo) error { return nil }
