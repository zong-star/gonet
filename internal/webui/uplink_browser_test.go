package webui

import (
	"context"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"gonet/internal/control"
	"gonet/internal/topology"
)

func TestUplinkBrowser(t *testing.T) {
	output := os.Getenv("GONET_UPLINK_BROWSER_OUTPUT")
	if output == "" {
		t.Skip("GONET_UPLINK_BROWSER_OUTPUT not set")
	}
	view := preciseContractView()
	view.SchemaVersion = 1
	view.Candidates = []control.Candidate{}
	view.PendingNodes = []topology.PendingNode{}
	view.PendingLinks = []topology.PendingLink{}
	app := newTestServer(t, &apiBackend{countingBackend: countingBackend{view: view}})
	defer app.Close()
	cookie, _ := testSession(t, app)
	server := httptest.NewUnstartedServer(nil)
	server.Config.Handler = app.Handler(server.Listener.Addr().String())
	server.StartTLS()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	script, err := filepath.Abs("../../docs/acceptance/gonet-uplink-optimization/verify-uplink.cjs")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, "node", script)
	command.Env = append(os.Environ(), "GONET_UPLINK_TEST_URL="+server.URL, "GONET_UPLINK_TEST_COOKIE="+cookie.Name+"="+cookie.Value)
	result, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("browser checks: %v\n%s", err, result)
	}
	t.Log(string(result))
}
