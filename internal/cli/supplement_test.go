package cli

import (
	"context"
	"github.com/gosnmp/gosnmp"
	"gonet/internal/collector/lldp"
	"gonet/internal/config"
	"io"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

func TestAddressSupplementOnlyReadsChassisAndHonorsExclusion(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	requests := [][]string{}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buffer := make([]byte, 4096)
		for {
			n, a, e := conn.ReadFromUDP(buffer)
			if e != nil {
				return
			}
			g := gosnmp.GoSNMP{Logger: gosnmp.NewLogger(log.New(io.Discard, "", 0))}
			req, e := g.SnmpDecodePacket(buffer[:n])
			if e != nil {
				continue
			}
			oids := []string{}
			vars := []gosnmp.SnmpPDU{}
			for _, p := range req.Variables {
				oids = append(oids, strings.TrimPrefix(p.Name, "."))
				switch strings.TrimPrefix(p.Name, ".") {
				case strings.TrimPrefix(lldp.LldpLocChassisIDSubtype, "."):
					vars = append(vars, gosnmp.SnmpPDU{Name: p.Name, Type: gosnmp.Integer, Value: 7})
				case strings.TrimPrefix(lldp.LldpLocChassisID, "."):
					vars = append(vars, gosnmp.SnmpPDU{Name: p.Name, Type: gosnmp.OctetString, Value: []byte("02:00:00:00:00:42")})
				}
			}
			mu.Lock()
			requests = append(requests, oids)
			mu.Unlock()
			reply := gosnmp.SnmpPacket{Version: gosnmp.Version2c, Community: req.Community, RequestID: req.RequestID, PDUType: gosnmp.GetResponse, Variables: vars}
			b, e := reply.MarshalMsg()
			if e == nil {
				_, _ = conn.WriteToUDP(b, a)
			}
		}
	}()
	t.Cleanup(func() { conn.Close(); wg.Wait() })
	t.Setenv("GONET_PROBE_TEST_COMMUNITY", "test-only")
	cfg := &config.Config{Discovery: config.DiscoveryConfig{ManagementCIDRs: []string{"127.0.0.0/8"}}, SNMP: config.SNMPConfig{Port: uint16(conn.LocalAddr().(*net.UDPAddr).Port), DefaultProfile: "test", Profiles: map[string]config.ProfileConfig{"test": {Version: "2c", CommunityEnv: "GONET_PROBE_TEST_COMMUNITY"}}}}
	keys := probeChassis(context.Background(), cfg, netip.MustParseAddr("127.0.0.1"))
	if len(keys) != 2 || keys[0] != "lldp:4:020000000042" || keys[1] != "lldp:7:020000000042" {
		t.Fatalf("unexpected identity hints: %v", keys)
	}
	cfg.Discovery.ExcludedCIDRs = []string{"127.0.0.1/32"}
	if got := probeChassis(context.Background(), cfg, netip.MustParseAddr("127.0.0.1")); got != nil {
		t.Fatal("excluded host was probed")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 1 || len(requests[0]) != 2 {
		t.Fatalf("probe issued more than the two chassis scalars: %v", requests)
	}
}
