package cli

import (
	"bytes"
	"strings"
	"testing"
)

// Persistent scan without database.dsn_env fails as a config error (exit 2).
func TestScanPersistentMissingDSN(t *testing.T) {
	t.Setenv("GONET_TEST_COMMUNITY", "x")
	cfg := writeCollectConfig(t, 60999)
	var out, errOut bytes.Buffer
	code := Run([]string{"scan", "--config", cfg, "--output", "-"}, &out, &errOut)
	if code != ExitUsage {
		t.Errorf("exit = %d, want %d; stderr=%s", code, ExitUsage, errOut.String())
	}
	if !strings.Contains(errOut.String(), "dsn_env") {
		t.Errorf("stderr = %q, want dsn_env mention", errOut.String())
	}
}

func TestScanPlanNeedsNeitherSNMPSecretsNorDatabase(t *testing.T) {
	t.Setenv("GONET_TEST_COMMUNITY", "")
	cfg := writeCollectConfig(t, 60999)
	var out, errOut bytes.Buffer
	if code := Run([]string{"scan", "--config", cfg, "--plan"}, &out, &errOut); code != ExitOK || !bytes.Contains(out.Bytes(), []byte(`"range_hosts"`)) {
		t.Fatalf("plan resolved network credentials: code=%d stderr=%s", code, errOut.String())
	}
}

func TestScanDryRunUnreachable(t *testing.T) {
	t.Setenv("GONET_TEST_COMMUNITY", "x")
	cfg := writeCollectConfig(t, 60999) // closed local UDP port
	var out, errOut bytes.Buffer
	code := Run([]string{"scan", "--config", cfg, "--dry-run", "--output", "-"}, &out, &errOut)
	if code != ExitNoResult {
		t.Errorf("exit = %d, want %d (no usable result); stderr=%s", code, ExitNoResult, errOut.String())
	}
	if !bytes.Contains(out.Bytes(), []byte(`"status"`)) {
		t.Errorf("output missing status: %s", out.String())
	}
}

func TestTopologyExportRequiresConfig(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run([]string{"topology", "export"}, &out, &errOut); code != ExitUsage {
		t.Errorf("exit = %d, want %d", code, ExitUsage)
	}
}

func TestTopologyExportBadState(t *testing.T) {
	t.Setenv("GONET_TEST_COMMUNITY", "x")
	cfg := writeCollectConfig(t, 161)
	var out, errOut bytes.Buffer
	if code := Run([]string{"topology", "export", "--config", cfg, "--state", "bogus"}, &out, &errOut); code != ExitUsage {
		t.Errorf("exit = %d, want %d", code, ExitUsage)
	}
}

// P06: a dry-run with a secret community never writes it to stdout or stderr.
func TestP06NoSecretInDryRunLogs(t *testing.T) {
	secret := "SECRET-COMMUNITY-9f3a"
	t.Setenv("GONET_TEST_COMMUNITY", secret)
	cfg := writeCollectConfig(t, 60999)
	var out, errOut bytes.Buffer
	Run([]string{"scan", "--config", cfg, "--dry-run", "--output", "-"}, &out, &errOut)
	for _, s := range []string{out.String(), errOut.String()} {
		if strings.Contains(s, secret) {
			t.Fatalf("secret leaked to CLI output/log: %q", s)
		}
	}
}

func TestScanExitCode(t *testing.T) {
	cases := map[string]int{
		"completed": ExitOK,
		"partial":   ExitPartial,
		"failed":    ExitNoResult,
		"aborted":   ExitInterrupted,
	}
	for status, want := range cases {
		if got := scanExitCode(status); got != want {
			t.Errorf("scanExitCode(%q) = %d, want %d", status, got, want)
		}
	}
}
