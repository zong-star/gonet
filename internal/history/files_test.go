package history

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func makeFile(t *testing.T, root, name string, stamp time.Time) {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.WriteFile(p, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, stamp, stamp); err != nil {
		t.Fatal(err)
	}
}
func TestPrune500BoundaryAndPreserveLatest(t *testing.T) {
	root := t.TempDir()
	now := time.Now()
	for i := 1; i <= 503; i++ {
		makeFile(t, root, fmt.Sprintf("scan-ui-%d.json", i), now.Add(time.Duration(i)*time.Second))
	}
	for _, n := range []string{"topology-latest.json", "topology-latest.svg", "latest-status.json", "console.log", "manual-snapshot.json", "scan-20261101.json"} {
		makeFile(t, root, n, now)
	}
	data, _ := json.Marshal(map[string]any{"scan_id": 1})
	if err := os.WriteFile(filepath.Join(root, "latest-status.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "scan-ui-9999.json"), 0700); err != nil {
		t.Fatal(err)
	}
	out, err := PruneOutputs(root, 500)
	if err != nil || out.Groups != 3 || out.Files != 3 {
		t.Fatalf("boundary: %+v %v", out, err)
	}
	for _, n := range []string{"scan-ui-1.json", "scan-ui-503.json", "topology-latest.json", "manual-snapshot.json", "console.log", "scan-20261101.json"} {
		if _, err := os.Stat(filepath.Join(root, n)); err != nil {
			t.Fatal("protected file deleted", n)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "scan-ui-2.json")); !os.IsNotExist(err) {
		t.Fatal("old unpinned file survived")
	}
	out, err = PruneOutputs(root, 500)
	if err != nil || out.Files != 0 {
		t.Fatal("repeat cleanup was not idempotent")
	}
}
func TestCLIBatchAndSubdirectories(t *testing.T) {
	root := t.TempDir()
	now := time.Now()
	stamp := "20261101-120000-001-abcdef"
	for _, name := range []string{"scan-" + stamp + ".json", "scan-" + stamp + ".log", "topology-export-" + stamp + ".json"} {
		makeFile(t, root, name, now)
	}
	for i := 1; i <= 2; i++ {
		makeFile(t, root, fmt.Sprintf("scan-ui-%d.json", i), now.Add(time.Duration(i)*time.Hour))
	}
	sub := filepath.Join(root, "diagnostics")
	if err := os.Mkdir(sub, 0700); err != nil {
		t.Fatal(err)
	}
	makeFile(t, sub, "scan-ui-99.json", now)
	out, err := PruneOutputs(root, 2)
	if err != nil || out.Groups != 1 || out.Files != 3 {
		t.Fatalf("CLI batch was not pruned together: %+v %v", out, err)
	}
	if _, err := os.Stat(filepath.Join(sub, "scan-ui-99.json")); err != nil {
		t.Fatal("cleanup recursed into diagnostics")
	}
	// A matching symlink must not become a removable history group.
	outside := t.TempDir()
	makeFile(t, outside, "keep.json", now)
	if err := os.Symlink(filepath.Join(outside, "keep.json"), filepath.Join(root, "scan-ui-999.json")); err == nil {
		if _, err := PruneOutputs(root, 2); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(filepath.Join(root, "scan-ui-999.json")); err != nil {
			t.Fatal("symlink was removed")
		}
		if _, err := os.Stat(filepath.Join(outside, "keep.json")); err != nil {
			t.Fatal("symlink target was removed")
		}
	}
}

func TestEqualFileTimesUseNumericScanOrder(t *testing.T) {
	root := t.TempDir()
	now := time.Now()
	for _, id := range []int{9, 10, 100} {
		makeFile(t, root, fmt.Sprintf("scan-ui-%d.json", id), now)
	}
	if _, err := PruneOutputs(root, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "scan-ui-9.json")); !os.IsNotExist(err) {
		t.Fatal("lexical ordering retained an older scan")
	}
}
