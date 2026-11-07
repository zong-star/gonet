package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHistoryPruneFilesOnlyUsesConfiguredLimit(t *testing.T) {
	dir := t.TempDir()
	raw, err := os.ReadFile("../../config/config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.yaml")
	if err = os.WriteFile(cfg, []byte(strings.Replace(string(raw), "keep_scans: 500", "keep_scans: 2", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	outputs := filepath.Join(dir, "outputs")
	if err = os.Mkdir(outputs, 0700); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 4; i++ {
		if err = os.WriteFile(filepath.Join(outputs, fmt.Sprintf("scan-ui-%d.json", i)), []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GONET_DATABASE_URL", "")
	var out, stderr bytes.Buffer
	if code := Run([]string{"history", "prune", "--config", cfg, "--output-dir", outputs, "--files-only"}, &out, &stderr); code != ExitOK {
		t.Fatalf("files-only cleanup failed: %d %s", code, &stderr)
	}
	var result struct {
		Keep  int `json:"keep_scans"`
		Files struct {
			Groups int `json:"groups"`
		} `json:"files"`
	}
	if err = json.Unmarshal(out.Bytes(), &result); err != nil || result.Keep != 2 || result.Files.Groups != 2 {
		t.Fatalf("wrong cleanup summary: %s error=%v", &out, err)
	}
	entries, err := os.ReadDir(outputs)
	if err != nil || len(entries) != 2 {
		t.Fatal("CLI did not prune generated files")
	}
	out.Reset()
	stderr.Reset()
	if code := Run([]string{"history", "prune", "--config", cfg, "--output-dir", outputs}, &out, &stderr); code != ExitUsage {
		t.Fatal("database cleanup accepted a missing DSN", code)
	}
}
