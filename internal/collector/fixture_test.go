package collector

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"gonet/internal/collector/lldp"
	"gonet/internal/collector/oidutil"
	"gonet/internal/collector/snmp"
	"gonet/internal/model"
)

// fixtureAgent is a minimal in-process SNMP agent backed by a sorted OID map.
// It answers GET, GETNEXT and GETBULK so the real Collector exercises the full
// network path against a replayable, sanitized fixture.
type fixtureAgent struct {
	requested  []string
	failScalar string
	mu         sync.Mutex
	oids       map[string]gosnmp.SnmpPDU
	order      []string
	seq        map[string][]any // per-OID GET value sequence (e.g. changing uptime)
	conn       *net.UDPConn
	wg         sync.WaitGroup
}

func startFixture(t *testing.T, oids map[string]gosnmp.SnmpPDU) *fixtureAgent {
	return startFixtureSeq(t, oids, nil)
}

func startFixtureSeq(t *testing.T, oids map[string]gosnmp.SnmpPDU, seq map[string][]any) *fixtureAgent {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	a := &fixtureAgent{oids: oids, seq: seq, conn: conn}
	for oid := range oids {
		a.order = append(a.order, oid)
	}
	sort.Slice(a.order, func(i, j int) bool { return oidutil.Compare(a.order[i], a.order[j]) < 0 })
	a.wg.Add(1)
	go a.serve()
	t.Cleanup(func() { _ = a.conn.Close(); a.wg.Wait() })
	return a
}

func (a *fixtureAgent) addr() string { return a.conn.LocalAddr().String() }

func (a *fixtureAgent) serve() {
	defer a.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, addr, err := a.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		pkt := decodeRequest(buf[:n])
		if pkt == nil {
			continue
		}
		resp := a.handle(pkt)
		_, _ = a.conn.WriteToUDP(resp, addr)
	}
}

func (a *fixtureAgent) handle(req *gosnmp.SnmpPacket) []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, v := range req.Variables {
		a.requested = append(a.requested, normOID(v.Name))
	}
	if req.PDUType == gosnmp.GetRequest && a.failScalar != "" {
		for _, v := range req.Variables {
			if normOID(v.Name) == a.failScalar {
				pkt := &gosnmp.SnmpPacket{Version: gosnmp.Version2c, Community: "public", PDUType: gosnmp.GetResponse, Error: gosnmp.GenErr}
				b, _ := pkt.MarshalMsg()
				return b
			}
		}
	}

	var vars []gosnmp.SnmpPDU
	switch req.PDUType {
	case gosnmp.GetRequest:
		for _, v := range req.Variables {
			oid := normOID(v.Name)
			if _, ok := a.oids[oid]; ok {
				vars = append(vars, a.getValue(oid))
			} else {
				vars = append(vars, gosnmp.SnmpPDU{Name: v.Name, Type: gosnmp.NoSuchObject, Value: nil})
			}
		}
	case gosnmp.GetNextRequest:
		vars = a.next(normOID(req.Variables[0].Name), 1)
	case gosnmp.GetBulkRequest:
		reps := int(req.MaxRepetitions)
		if reps < 1 {
			reps = 1
		}
		vars = a.next(normOID(req.Variables[0].Name), reps)
	default:
		return nil
	}
	return marshalResponse(vars)
}

func normOID(s string) string {
	return strings.TrimPrefix(s, ".")
}

// getValue pops the next value from a per-OID sequence if one is configured,
// otherwise returns the static fixture value.
func (a *fixtureAgent) getValue(oid string) gosnmp.SnmpPDU {
	p := a.oids[oid]
	if vals, ok := a.seq[oid]; ok && len(vals) > 0 {
		p.Value = vals[0]
		a.seq[oid] = vals[1:]
	}
	return p
}

func (a *fixtureAgent) next(start string, count int) []gosnmp.SnmpPDU {
	idx := sort.Search(len(a.order), func(i int) bool {
		return oidutil.Compare(a.order[i], start) > 0
	})
	var out []gosnmp.SnmpPDU
	for i := idx; i < len(a.order) && len(out) < count; i++ {
		out = append(out, a.oids[a.order[i]])
	}
	if len(out) == 0 {
		out = append(out, gosnmp.SnmpPDU{Name: start, Type: gosnmp.EndOfMibView, Value: nil})
	}
	return out
}

func marshalResponse(vars []gosnmp.SnmpPDU) []byte {
	pkt := &gosnmp.SnmpPacket{
		Version:   gosnmp.Version2c,
		Community: "public",
		PDUType:   gosnmp.GetResponse,
		Variables: vars,
	}
	b, err := pkt.MarshalMsg()
	if err != nil {
		return nil
	}
	return b
}

func decodeRequest(b []byte) *gosnmp.SnmpPacket {
	g := &gosnmp.GoSNMP{Logger: gosnmp.NewLogger(log.New(io.Discard, "", 0))}
	pkt, err := g.SnmpDecodePacket(b)
	if err != nil {
		return nil
	}
	return pkt
}

func oidStr(base string, suffix ...string) string {
	s := base
	for _, x := range suffix {
		s += "." + x
	}
	return s
}

func sampleFixture() map[string]gosnmp.SnmpPDU {
	o := map[string]gosnmp.SnmpPDU{}
	add := func(oid string, typ gosnmp.Asn1BER, val any) {
		o[oid] = gosnmp.SnmpPDU{Name: oid, Type: typ, Value: val}
	}
	add(lldp.SysObjectID, gosnmp.ObjectIdentifier, "1.3.6.1.4.1.99999.1.1")
	add(lldp.SysUpTime, gosnmp.TimeTicks, uint32(1234567))
	add(lldp.SysName, gosnmp.OctetString, []byte("core-sw1"))
	add(lldp.SysDescr, gosnmp.OctetString, []byte("Example Networks Core Switch"))
	add(lldp.LldpStatsRemTablesLastChangeTime, gosnmp.TimeTicks, uint32(42))

	add(lldp.LldpLocChassisIDSubtype, gosnmp.Integer, 4)
	add(lldp.LldpLocChassisID, gosnmp.OctetString, []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	add(lldp.LldpLocSysCapSupported, gosnmp.OctetString, []byte{0x20})
	add(lldp.LldpLocSysCapEnabled, gosnmp.OctetString, []byte{0x20})

	// admin status (rx enabled) for local ports 1 and 2
	add(oidStr(lldp.LldpPortConfigAdminStatus, "1"), gosnmp.Integer, 3)
	add(oidStr(lldp.LldpPortConfigAdminStatus, "2"), gosnmp.Integer, 3)

	// local ports
	add(oidStr(lldp.LldpLocPortIDSubtype, "1"), gosnmp.Integer, 5)
	add(oidStr(lldp.LldpLocPortID, "1"), gosnmp.OctetString, []byte("GigabitEthernet1/0/1"))
	add(oidStr(lldp.LldpLocPortDesc, "1"), gosnmp.OctetString, []byte("uplink to agg-a"))
	add(oidStr(lldp.LldpLocPortIDSubtype, "2"), gosnmp.Integer, 5)
	add(oidStr(lldp.LldpLocPortID, "2"), gosnmp.OctetString, []byte("GigabitEthernet1/0/2"))
	add(oidStr(lldp.LldpLocPortDesc, "2"), gosnmp.OctetString, []byte("uplink to agg-b"))

	// remote table: two neighbors (timeMark=7)
	rem := func(col, lpn, ri string, typ gosnmp.Asn1BER, val any) {
		add(oidStr(col, "7", lpn, ri), typ, val)
	}
	rem(lldp.LldpRemChassisIDSubtype, "1", "1", gosnmp.Integer, 4)
	rem(lldp.LldpRemChassisID, "1", "1", gosnmp.OctetString, []byte{0x00, 0x22, 0x33, 0x44, 0x55, 0x66})
	rem(lldp.LldpRemPortIDSubtype, "1", "1", gosnmp.Integer, 5)
	rem(lldp.LldpRemPortID, "1", "1", gosnmp.OctetString, []byte("GigabitEthernet0/1"))
	rem(lldp.LldpRemPortDesc, "1", "1", gosnmp.OctetString, []byte("to core"))
	rem(lldp.LldpRemSysName, "1", "1", gosnmp.OctetString, []byte("agg-a"))
	rem(lldp.LldpRemSysDesc, "1", "1", gosnmp.OctetString, []byte("Aggregation Switch A"))
	rem(lldp.LldpRemSysCapSupported, "1", "1", gosnmp.OctetString, []byte{0x20})
	rem(lldp.LldpRemSysCapEnabled, "1", "1", gosnmp.OctetString, []byte{0x20})

	rem(lldp.LldpRemChassisIDSubtype, "2", "1", gosnmp.Integer, 4)
	rem(lldp.LldpRemChassisID, "2", "1", gosnmp.OctetString, []byte{0x00, 0x22, 0x33, 0x44, 0x55, 0x77})
	rem(lldp.LldpRemPortIDSubtype, "2", "1", gosnmp.Integer, 5)
	rem(lldp.LldpRemPortID, "2", "1", gosnmp.OctetString, []byte("GigabitEthernet0/1"))
	rem(lldp.LldpRemSysName, "2", "1", gosnmp.OctetString, []byte("agg-b"))
	rem(lldp.LldpRemSysCapSupported, "2", "1", gosnmp.OctetString, []byte{0x20})
	rem(lldp.LldpRemSysCapEnabled, "2", "1", gosnmp.OctetString, []byte{0x20})

	// management address: neighbor 1 advertises 192.0.2.11 (IPv4)
	add(oidStr(lldp.LldpRemManAddrTable+".1", "3", "7", "1", "1", "1", "4", "192", "0", "2", "11"), gosnmp.Integer, 2)

	// interfaces
	iface := func(idx string, desc, name, alias string, typ int, mac []byte) {
		add(oidStr(lldp.IfDescr, idx), gosnmp.OctetString, []byte(desc))
		add(oidStr(lldp.IfType, idx), gosnmp.Integer, typ)
		add(oidStr(lldp.IfPhysAddress, idx), gosnmp.OctetString, mac)
		add(oidStr(lldp.IfName, idx), gosnmp.OctetString, []byte(name))
		add(oidStr(lldp.IfAlias, idx), gosnmp.OctetString, []byte(alias))
	}
	iface("101", "GigabitEthernet1/0/1", "GigabitEthernet1/0/1", "to-agg-a", 6, []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	iface("102", "GigabitEthernet1/0/2", "GigabitEthernet1/0/2", "to-agg-b", 6, []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x56})
	return o
}

// TestCollectFixture drives the real Collector against a sanitized fixture
// agent (simulated collection) and asserts the derived conclusions.
func TestCollectFixture(t *testing.T) {
	agent := startFixture(t, sampleFixture())
	host, portStr, _ := net.SplitHostPort(agent.addr())
	port, _ := strconv.Atoi(portStr)

	c := New(Options{
		CollectManagementAddresses: true, // explicit opt-in regression for standard agents
		Params: snmp.Params{
			Port:           uint16(port),
			Timeout:        time.Second,
			Retries:        0,
			MaxRepetitions: 20,
			MaxPDUs:        500,
			Version:        "2c",
			Community:      "public",
		},
		MaxNeighbors:       4096,
		ConsistencyRetries: 0,
		ViewVerified:       true,
		DeviceTimeout:      5 * time.Second,
	})
	snap, err := c.Collect(context.Background(), model.DiscoveryTarget{Address: mustAddr(host)})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if !snap.CollectionComplete {
		t.Errorf("CollectionComplete = false, issues: %+v", snap.Issues)
	}
	if !snap.SnapshotStable {
		t.Errorf("SnapshotStable = false, issues: %+v", snap.Issues)
	}
	if !snap.AbsenceEligible {
		t.Errorf("AbsenceEligible = false (want true for verified fixture), issues: %+v", snap.Issues)
	}
	if len(snap.Neighbors) != 2 {
		t.Errorf("neighbors = %d, want 2", len(snap.Neighbors))
	}
	if len(snap.LocalPorts) != 2 {
		t.Errorf("local ports = %d, want 2", len(snap.LocalPorts))
	}
	if len(snap.Device.Chassis.Raw) != 6 {
		t.Errorf("chassis raw len = %d, want 6", len(snap.Device.Chassis.Raw))
	}
	// local port 1 must map to ifIndex 101, not locPortNum 1
	lp := snap.LocalPorts[0]
	if lp.Number != 1 || lp.IfIndex == nil || *lp.IfIndex != 101 {
		t.Errorf("local port 1 mapping wrong: number=%d ifIndex=%v", lp.Number, lp.IfIndex)
	}
	// management address decoded from the OID index
	if len(snap.Neighbors[0].MgmtAddresses) != 1 || snap.Neighbors[0].MgmtAddresses[0].String() != "192.0.2.11" {
		t.Errorf("neighbor 1 mgmt addresses = %v, want [192.0.2.11]", snap.Neighbors[0].MgmtAddresses)
	}

	// JSON round-trip and example artifact.
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back["schema_version"] != float64(1) {
		t.Errorf("schema_version = %v, want 1", back["schema_version"])
	}
	examplePath := filepath.Join("..", "..", "testdata", "snapshot.example.json")
	if err := os.MkdirAll(filepath.Dir(examplePath), 0o755); err == nil {
		_ = os.WriteFile(examplePath, append(data, '\n'), 0o644)
	}
}

// C08 (retry): a device whose uptime restarts during both passes must trigger
// exactly one re-collection, end unstable, and never stitch two passes.
func TestCollectStabilityRetry(t *testing.T) {
	agent := startFixtureSeq(t, sampleFixture(), map[string][]any{
		lldp.SysUpTime: {uint32(1000), uint32(900), uint32(500), uint32(400)},
	})
	host, portStr, _ := net.SplitHostPort(agent.addr())
	port, _ := strconv.Atoi(portStr)

	c := New(Options{
		Params: snmp.Params{
			Port:           uint16(port),
			Timeout:        time.Second,
			Retries:        0,
			MaxRepetitions: 20,
			MaxPDUs:        500,
			Version:        "2c",
			Community:      "public",
		},
		MaxNeighbors:       4096,
		ConsistencyRetries: 1,
		ViewVerified:       true,
		DeviceTimeout:      5 * time.Second,
	})
	snap, err := c.Collect(context.Background(), model.DiscoveryTarget{Address: mustAddr(host)})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if snap.SnapshotStable {
		t.Error("SnapshotStable = true, want false (both passes unstable)")
	}
	if snap.AbsenceEligible {
		t.Error("AbsenceEligible = true, want false for unstable snapshot")
	}
	// The final pass must be the second one (500 -> 400), not pass 1 (1000->900)
	// and not a mix.
	if snap.Device.UptimeBefore != 500 || snap.Device.UptimeAfter != 400 {
		t.Errorf("uptime = %d -> %d, want 500 -> 400 (pass 2 only)",
			snap.Device.UptimeBefore, snap.Device.UptimeAfter)
	}
	if len(snap.Neighbors) != 2 {
		t.Errorf("neighbors = %d, want 2", len(snap.Neighbors))
	}
}

func mustAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}
