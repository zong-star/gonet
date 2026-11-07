package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCollectionFrequencyHotReloadShorterInterval(t *testing.T) {
	raw, e := os.ReadFile("../../config/config.example.yaml")
	if e != nil {
		t.Fatal(e)
	}
	raw = []byte(strings.Replace(string(raw), "interval: 4m", "interval: 1m", 1))
	path := filepath.Join(t.TempDir(), "config.yaml")
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	b := &consoleBackend{configPath: path, intervalChanged: make(chan struct{}, 1)}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	b.intervalChanged <- struct{}{}
	if !b.waitInterfaceStatus(ctx, time.Now().Add(-2*time.Minute), 24*time.Hour) {
		t.Fatal("shorter saved interval did not reschedule a day-long wait")
	}
}
