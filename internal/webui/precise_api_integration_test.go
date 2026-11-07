package webui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gonet/internal/auth"
	"gonet/internal/control"
	"gonet/internal/model"
	"gonet/internal/store/postgres"
	"gonet/internal/topology"
)

func TestCompactAPIKeyAndAudit(t *testing.T) {
	backend := &countingBackend{view: apiFixture()}
	s := newTestServer(t, backend)
	defer s.Close()
	var log bytes.Buffer
	s.auditLogger = slog.New(slog.NewJSONHandler(&log, nil))
	checkCompactAPIKey(t, s)
	output := log.String()
	for _, expected := range []string{`"caller":"key:1"`, `"route":"topology","device_id":"","status":403,"result_count":0`,
		`"route":"neighbors","device_id":"1","status":200`, `"request_id":`, `"duration_ms":`, `"time":`} {
		if !strings.Contains(output, expected) {
			t.Fatalf("audit did not contain %s", expected)
		}
	}
	for _, forbidden := range []string{"gonet_sk_", "Authorization", "unique-sensitive-search", "key_hash"} {
		if strings.Contains(output, forbidden) {
			t.Fatal("audit logged secret input")
		}
	}
}

func checkCompactAPIKey(t *testing.T, s *Server) {
	t.Helper()
	h := s.Handler(testHost)
	cookie, csrf := testSession(t, s)
	admin := map[string]string{"Content-Type": "application/json", "X-GoNet-Token": csrf}
	w := callAuth(h, "POST", apiKeyPath, `{"name":"Precise API","allowed_ips":["192.0.2.1"],"profile":"topology_compact"}`, cookie, admin)
	var created struct {
		postgres.APIKey
		Key string `json:"key"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil || w.Code != 201 || created.Profile != auth.APITopologyCompact || created.Key == "" {
		t.Fatalf("creating compact API Key: HTTP %d", w.Code)
	}
	bearer := map[string]string{"Authorization": "Bearer " + created.Key}
	if w := callAuth(h, "GET", "/api/v1/topology", "", nil, bearer); w.Code != 403 || !strings.Contains(w.Body.String(), "API_ROUTE_NOT_ALLOWED") {
		t.Fatal("compact key accessed the complete topology")
	}
	if w := callAuth(h, "GET", apiKeyPath, "", nil, bearer); w.Code != 401 {
		t.Fatal("compact key accessed administrator management")
	}
	if w := callAuth(h, "HEAD", "/api/v1/topology/summary", "", nil, bearer); w.Code != 405 || w.Header().Get("Allow") != "GET" {
		t.Fatal("compact key must be GET only")
	}
	for _, route := range []string{"/api/v1/devices?query=unique-sensitive-search", "/api/v1/devices/1", "/api/v1/devices/1/uplink-path", "/api/v1/topology/summary"} {
		if w := callAuth(h, "GET", route, "", nil, bearer); w.Code != 200 {
			t.Fatalf("compact allowlist %s: HTTP %d", route, w.Code)
		}
	}
	for _, route := range []string{"/api/v1/devices/1", "/api/v1/devices/1/neighbors", "/api/v1/devices/1/uplink-path", "/api/v1/topology/summary"} {
		if w := callAuth(h, "GET", route+"?schema_version=2", "", nil, bearer); w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"schema_version":2`)) {
			t.Fatalf("compact schema-v2 allowlist %s: HTTP %d", route, w.Code)
		}
	}
	if w := callAuth(h, "GET", "/api/v1/topology?schema_version=2", "", nil, bearer); w.Code != 403 {
		t.Fatal("schema selection bypassed the compact route restriction")
	}
	neighbors := decodeAPI(t, callAuth(h, "GET", "/api/v1/devices/1/neighbors", "", nil, bearer))
	if neighbors.Meta.State != "active" || !bytes.Contains(neighbors.Data, []byte(`"returned_link_count"`)) {
		t.Fatal("compact key did not default to the limited neighbor response")
	}
	keyRoute := apiKeyPath + "/" + idString(created.ID)
	if w := callAuth(h, "PATCH", keyRoute, `{"allowed_ips":["198.51.100.8"]}`, cookie, admin); w.Code != 200 {
		t.Fatal("cannot edit compact key allowlist")
	}
	if w := callAuth(h, "GET", "/api/v1/topology/summary", "", nil, bearer); w.Code != 403 || !strings.Contains(w.Body.String(), "IP_NOT_ALLOWED") {
		t.Fatal("IP restriction did not take effect immediately")
	}
	if w := callAuth(h, "DELETE", keyRoute, "", cookie, admin); w.Code != 204 {
		t.Fatal("cannot revoke compact key")
	}
	if w := callAuth(h, "GET", "/api/v1/topology/summary", "", nil, bearer); w.Code != 401 {
		t.Fatal("revocation did not take effect immediately")
	}
	if w := callAuth(h, "GET", "/api/v1/topology/summary?schema_version=2", "", nil, bearer); w.Code != 401 {
		t.Fatal("revocation did not take effect for schema-v2")
	}
}

// These are HTTP responses from the production handler, over TLS, using a
// sanitized topology fixture. The optional path refreshes contract fixtures.
func TestPreciseTopologyContractSamples(t *testing.T) {
	view := preciseContractView()
	var current atomic.Pointer[control.View]
	current.Store(view)
	backend := &apiBackend{read: func(context.Context) (*control.View, error) { return current.Load(), nil }}
	s := newTestServer(t, backend)
	defer s.Close()
	s.auditLogger = slog.New(slog.NewTextHandler(io.Discard, nil))
	newKey := func(name string, ip string) string {
		t.Helper()
		key, preview, hash, err := auth.GenerateAPIKey()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.apiKeys.CreateAPIKey(context.Background(), postgres.APIKey{Name: name, Preview: preview,
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix(ip)}, Profile: auth.APITopologyCompact}, hash); err != nil {
			t.Fatal(err)
		}
		return key
	}
	key := newKey("contract", "127.0.0.1/32")
	denied := newKey("outside", "192.0.2.5/32")
	server := httptest.NewTLSServer(s.Handler(testHost))
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	type responseSample struct {
		Name   string          `json:"name"`
		Path   string          `json:"path"`
		Status int             `json:"status"`
		Body   json.RawMessage `json:"body"`
	}
	samples := []responseSample{}
	capture := func(name, path, token string, status int) {
		t.Helper()
		request, err := http.NewRequest("GET", server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = testHost
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != status || !json.Valid(body) || response.Header.Get("X-Request-ID") == "" {
			t.Fatalf("%s HTTP %d: %s", name, response.StatusCode, body)
		}
		samples = append(samples, responseSample{name, path, status, body})
	}
	capture("management_ip", "/api/v1/devices?query=192.0.2.1", key, 200)
	capture("device_details", "/api/v1/devices/1", key, 200)
	capture("compact_neighbors", "/api/v1/devices/1/neighbors", key, 200)
	capture("lag_and_physical_path", "/api/v1/devices/1/uplink-path?include_unverified=true", key, 200)
	capture("no_confirmed_path", "/api/v1/devices/1/uplink-path?max_hops=1", key, 200)
	capture("topology_summary", "/api/v1/topology/summary", key, 200)
	capture("invalid_query", "/api/v1/devices?query=Access&limit=6", key, 400)
	capture("unauthenticated", "/api/v1/devices/1/uplink-path", "", 401)
	capture("ip_not_allowed", "/api/v1/topology/summary", denied, 403)
	capture("device_not_found", "/api/v1/devices/999/uplink-path", key, 404)
	capture("full_topology_denied", "/api/v1/topology", key, 403)
	oversized := pathChain(2)
	oversized.Links[0].PortAName = strings.Repeat("端", maxCompactAPIBytes)
	current.Store(oversized)
	capture("result_too_large", "/api/v1/devices/1/uplink-path", key, 422)
	writeSamples := func(env string) {
		path := os.Getenv(env)
		if path == "" {
			return
		}
		payload, err := json.MarshalIndent(samples, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(payload, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeSamples("GONET_PRECISE_SAMPLE_OUTPUT")
	samples = nil
	current.Store(view)
	capture("device_v2", "/api/v1/devices/1?schema_version=2", key, 200)
	capture("neighbors_v2", "/api/v1/devices/1/neighbors?schema_version=2", key, 200)
	capture("summary_v2", "/api/v1/topology/summary?schema_version=2", key, 200)
	capture("uplink_v2", "/api/v1/devices/1/uplink-path?schema_version=2&include_unverified=true", key, 200)
	capture("uplink_zero_v2", "/api/v1/devices/3/uplink-path?schema_version=2", key, 200)
	capture("uplink_empty_v2", "/api/v1/devices/1/uplink-path?schema_version=2&max_hops=1", key, 200)
	capture("uplink_invalid_v2", "/api/v1/devices/1/uplink-path?schema_version=2&max_paths=3", key, 400)
	tooLarge := pathChain(2)
	longName := strings.Repeat("端", maxCompactAPIBytes)
	tooLarge.Evidence = &postgres.TopologyEvidence{Links: map[int64]postgres.PhysicalLinkEvidence{
		1: {A: postgres.LinkEndpointEvidence{IfName: &longName}},
	}}
	current.Store(tooLarge)
	capture("uplink_oversized_v2", "/api/v1/devices/1/uplink-path?schema_version=2", key, 422)
	writeSamples("GONET_TOPOLOGY_V2_SAMPLE_OUTPUT")
}

func preciseContractView() *control.View {
	view := pathChain(3)
	view.LatestScanStatus = "partial"
	finished := time.Date(2026, 11, 4, 5, 0, 0, 0, time.UTC)
	view.LatestScanFinishedAt = &finished
	for i := range view.Devices {
		device := &view.Devices[i]
		device.Status, device.IdentityState, device.Vendor, device.Model = "collected", "verified", "H3C", "S5130"
		device.LastSeenAt = finished
	}
	for i := range view.Links {
		link := &view.Links[i]
		link.DeviceAName, link.DeviceBName = view.Devices[link.DeviceAID-1].Name, view.Devices[link.DeviceBID-1].Name
		link.Fresh = true
	}
	view.CandidateLinks = []topology.PendingLink{{
		LocalDevice: 2, LocalPortNum: 14, ObservationID: 200, ObservedAt: finished,
		Chassis: model.TypedID{Subtype: 4, Raw: []byte{2, 0, 0, 0, 0, 4}}, RemotePort: model.TypedID{Subtype: 7, Raw: []byte("remote-port")},
		ReasonCodes: []string{"PORT_UNRESOLVED"},
	}}
	view.Evidence = &postgres.TopologyEvidence{Links: map[int64]postgres.PhysicalLinkEvidence{}, LAG: map[int64]postgres.DeviceLAGEvidence{}}
	parallel := view.Links[0]
	parallel.ID, parallel.PortAID, parallel.PortBID = 3, 22, 23
	parallel.PortAName, parallel.PortBName = "Ten-GigabitEthernet1/0/28", "Ten-GigabitEthernet1/0/4"
	view.Links = append(view.Links, parallel)
	for _, link := range []postgres.ExportLink{view.Links[0], parallel} {
		a, b := int32(link.PortAID), int32(link.PortBID)
		nameA, nameB := link.PortAName, link.PortBName
		view.Evidence.Links[link.ID] = postgres.PhysicalLinkEvidence{A: postgres.LinkEndpointEvidence{IfIndex: &a, IfName: &nameA}, B: postgres.LinkEndpointEvidence{IfIndex: &b, IfName: &nameB},
			Observations: []postgres.ObservationRef{{ID: 100 + link.ID, ObserverID: 1}}}
		for dev, index := range map[int64]int32{1: a, 2: b} {
			facts := view.Evidence.LAG[dev]
			facts.Complete = true
			facts.Members = append(facts.Members, postgres.LAGMemberEvidence{LAGMember: model.LAGMember{
				AggregateIfIndex: 101, MemberIfIndex: index, Mode: "lacp", Status: "confirmed", Source: "ieee_lag",
			}, AggregateName: fmt.Sprintf("Bridge-Aggregation%d", dev), Endpoint: postgres.LinkEndpointEvidence{IfIndex: int32Pointer(101), IfName: stringPointer(fmt.Sprintf("Bridge-Aggregation%d", dev))}})
			view.Evidence.LAG[dev] = facts
		}
	}
	return view
}
