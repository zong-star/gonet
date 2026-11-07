package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run([]string{"version"}, &out, &errOut)
	if code != ExitOK {
		t.Fatalf("version exit = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "gonet "+Version) {
		t.Errorf("version output %q missing version", out.String())
	}
	if errOut.Len() != 0 {
		t.Errorf("version wrote to stderr: %q", errOut.String())
	}
}

func TestNoArgsUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run(nil, &out, &errOut)
	if code != ExitUsage {
		t.Fatalf("no-args exit = %d, want %d", code, ExitUsage)
	}
}

func TestUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Run([]string{"bogus"}, &out, &errOut)
	if code != ExitUsage {
		t.Fatalf("unknown command exit = %d, want %d", code, ExitUsage)
	}
}
