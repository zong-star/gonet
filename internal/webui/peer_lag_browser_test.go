package webui

import (
	"context"
	"gonet/internal/control"
	"gonet/internal/model"
	"gonet/internal/topology"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestPeerLAGBrowser(t *testing.T) {
	output := os.Getenv("GONET_PEER_LAG_BROWSER_OUTPUT")
	if output == "" {
		t.Skip("browser acceptance output not requested")
	}
	view := peerLAGView()
	if os.Getenv("GONET_INTERFACE_STATUS_BROWSER") != "" {
		now := time.Now().UTC()
		a := model.InterfaceStatus{AdminStatus: "up", OperStatus: "up", StatusCollectedAt: &now, StatusCollectionState: "success"}
		b := a
		for i := range view.Links {
			l := &view.Links[i]
			b = a
			switch l.ID {
			case 253:
				b.OperStatus = "down"
			case 65:
				b.AdminStatus = "down"
				b.OperStatus = "down"
			case 66:
				b.StatusCollectionState = "failed"
			}
			l.LinkInterfaceStatus = model.LinkStatus(a, b, now, 12*time.Minute)
		}
	}

	view.Candidates = []control.Candidate{}
	view.PendingNodes = []topology.PendingNode{}
	view.PendingLinks = []topology.PendingLink{}
	view.Inventory = []control.InventoryStatus{}
	view.ProbePool = []control.Probe{}
	for i := range view.Devices {
		view.Devices[i].AccessAddresses = []string{}
	}
	app := newTestServer(t, &apiBackend{countingBackend: countingBackend{view: view}})
	defer app.Close()
	cookie, _ := testSession(t, app)
	server := httptest.NewUnstartedServer(nil)
	server.Config.Handler = app.Handler(server.Listener.Addr().String())
	server.StartTLS()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	scriptPath := "../../docs/acceptance/gonet-peer-lag/verify-browser.cjs"
	if os.Getenv("GONET_INTERFACE_STATUS_BROWSER") != "" {
		scriptPath = "../../docs/acceptance/interface-status-2026-11-06/verify-browser.cjs"
	}
	script, e := filepath.Abs(scriptPath)
	if e != nil {
		t.Fatal(e)
	}
	command := exec.CommandContext(ctx, "node", script)
	command.Env = append(os.Environ(), "GONET_PEER_TEST_URL="+server.URL, "GONET_PEER_TEST_COOKIE="+cookie.Name+"="+cookie.Value)
	result, e := command.CombinedOutput()
	if e != nil {
		t.Fatalf("browser acceptance: %v\n%s", e, result)
	}
	t.Log(string(result))
}
