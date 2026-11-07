package webui

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"gonet/internal/auth"
	"gonet/internal/control"
	"gonet/internal/store/postgres"
	"gonet/internal/topology"
)

// Explicitly opt-in, isolated browser service. It has no database or collector.
func TestAuthBrowserFixture(t *testing.T) {
	root := os.Getenv("GONET_AUTH_FIXTURE_DIR")
	if root == "" {
		t.Skip("browser fixture is opt-in")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	view := authFixtureView()
	before, _ := json.Marshal(view)
	digest := sha256.Sum256(before)
	b := &countingBackend{view: view}
	app := newTestServer(t, b)
	defer app.Close()
	app.authConfig.CookieSecure = false
	if os.Getenv("GONET_AGENT_API_ENABLED") == "true" {
		token, _, err := auth.GenerateAgentToken()
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(root, "agent.client-token"), []byte(token), 0600); err != nil {
			t.Fatal(err)
		}
		seedTestKey(t, app, token)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:18787")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: app.Handler(listener.Addr().String()), ReadHeaderTimeout: 5 * time.Second}
	defer server.Close()
	go server.Serve(listener)
	// HTTPS test upstream uses Secure cookies, and otherwise the same application.
	secure := newTestServer(t, b)
	secure.apiKeys = app.apiKeys
	secure.authConfig.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	defer secure.Close()
	tlsUpstream, err := net.Listen("tcp", "127.0.0.1:18788")
	if err != nil {
		t.Fatal(err)
	}
	secureServer := &http.Server{Handler: secure.Handler(tlsUpstream.Addr().String()), ReadHeaderTimeout: 5 * time.Second}
	defer secureServer.Close()
	go secureServer.Serve(tlsUpstream)
	makeFixtureCertificate(t, root)
	if err = os.WriteFile(filepath.Join(root, "ready"), []byte("http://127.0.0.1:18787"), 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Minute)
	for time.Now().Before(deadline) {
		if _, err = os.Stat(filepath.Join(root, "stop")); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	after, _ := json.Marshal(view)
	afterDigest := sha256.Sum256(after)
	result := map[string]any{"fixture_sha256_before": hex.EncodeToString(digest[:]), "fixture_sha256_after": hex.EncodeToString(afterDigest[:]), "reads": b.reads.Load(), "settings_writes": b.writes.Load(), "scans": b.scans.Load(), "unchanged": digest == afterDigest}
	encoded, _ := json.MarshalIndent(result, "", "  ")
	os.WriteFile(filepath.Join(root, "backend-evidence.json"), encoded, 0600)
	if digest != afterDigest {
		t.Fatal("fixture mutated")
	}
}
func authFixtureView() *control.View {
	finished := time.Date(2026, 11, 2, 4, 0, 0, 0, time.UTC)
	v := &control.View{SchemaVersion: 1, GeneratedAt: finished, LatestScanID: 30, LatestScanStatus: "partial", LatestScanFinishedAt: &finished, Fresh: true, CoverageGap: true, CoreIDs: []int64{1}, Devices: []control.Device{}, Links: []postgres.ExportLink{}, Candidates: []control.Candidate{}}
	v.PendingLinks = []topology.PendingLink{}
	v.PendingNodes = []topology.PendingNode{}
	v.ProbePool = []control.Probe{}
	for i, name := range []string{"实验核心", "实验汇聚 A", "实验汇聚 B", "实验接入"} {
		depth := min(i, 2)
		v.Devices = append(v.Devices, control.Device{ExportDevice: postgres.ExportDevice{ID: int64(i + 1), Kind: "switch", SysName: name, IdentityState: "verified", DiscoveryDepth: &depth, AccessAddresses: []string{"192.0.2." + strconv.Itoa(i+1)}, LastSeenAt: finished}, Name: name, Vendor: "Fixture", Model: "Test Switch", Status: "collected", MAC: "02000000000" + strconv.Itoa(i+1)})
	}
	for i, pair := range [][2]int64{{1, 2}, {1, 2}, {1, 3}, {2, 4}, {3, 4}} {
		a, z := pair[0], pair[1]
		scan := int64(30)
		v.Links = append(v.Links, postgres.ExportLink{ID: int64(i + 1), DeviceAID: a, DeviceBID: z, DeviceAName: v.Devices[a-1].Name, DeviceBName: v.Devices[z-1].Name, PortAID: int64(100 + i*2), PortBID: int64(101 + i*2), PortAName: "GE1/0/" + strconv.Itoa(i+1), PortBName: "GE1/0/" + strconv.Itoa(i+1), Confidence: "bidirectional", DiscoveryState: "active", Fresh: true, FirstSeenAt: finished, LastSeenAt: finished, LastSeenScanID: &scan})
		v.Devices[a-1].LinkCount++
		v.Devices[z-1].LinkCount++
	}
	v.Counts = control.Counts{Confirmed: 4, Collected: 4, Switches: 4}
	return v
}
func makeFixtureCertificate(t *testing.T, root string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "GoNet isolated fixture"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "fixture.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "fixture.key"), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); err != nil {
		t.Fatal(err)
	}
}
