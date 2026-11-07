package secretfile

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCredentialRoundTripAndRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config", "snmp.secret")
	rollback, err := Store(path, "fixture-community-one")
	if err != nil {
		t.Fatal(err)
	}
	value, err := Read(path)
	if err != nil || value != "fixture-community-one" {
		t.Fatal("credential did not survive persistence", err)
	}
	blob, err := os.ReadFile(path)
	if err != nil || runtime.GOOS == "windows" && bytes.Contains(blob, []byte(value)) {
		t.Fatal("Windows credential was not protected", err)
	}
	rollbackSecond, err := Store(path, "fixture-community-two")
	if err != nil {
		t.Fatal(err)
	}
	if err = rollbackSecond(); err != nil {
		t.Fatal(err)
	}
	value, err = Read(path)
	if err != nil || value != "fixture-community-one" {
		t.Fatal("old credential not restored", err)
	}
	if err = rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("failed first save left a credential file")
	}
}

func TestCredentialFileRejectsInvalidFormat(t *testing.T) {
	p := filepath.Join(t.TempDir(), "invalid.secret")
	if err := os.WriteFile(p, []byte("not a managed credential"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(p); err == nil {
		t.Fatal("unprotected/invalid credential accepted")
	}
}
