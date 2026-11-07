package snmp

import (
	"io"
	"log"
	"net"
	"sync"
	"testing"

	"github.com/gosnmp/gosnmp"
)

// fakeAgent is an in-process UDP fake SNMP agent on loopback. It records every
// request and serves a scripted queue of raw v2c response bytes. When respond
// is false it acts as a black hole (reads and drops), simulating a timeout.
type fakeAgent struct {
	mu      sync.Mutex
	resps   [][]byte
	reqs    [][]byte
	respond bool
	conn    *net.UDPConn
	wg      sync.WaitGroup
}

func startFakeAgent(t *testing.T, respond bool, resps ...[]byte) *fakeAgent {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	a := &fakeAgent{resps: resps, respond: respond, conn: conn}
	a.wg.Add(1)
	go a.serve()
	t.Cleanup(func() {
		_ = a.conn.Close()
		a.wg.Wait()
	})
	return a
}

func (a *fakeAgent) serve() {
	defer a.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, addr, err := a.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		a.mu.Lock()
		a.reqs = append(a.reqs, append([]byte(nil), buf[:n]...))
		if !a.respond {
			a.mu.Unlock()
			continue
		}
		if len(a.resps) > 0 {
			resp := a.resps[0]
			a.resps = a.resps[1:]
			a.mu.Unlock()
			_, _ = a.conn.WriteToUDP(resp, addr)
		} else {
			a.mu.Unlock()
		}
	}
}

func (a *fakeAgent) addr() string { return a.conn.LocalAddr().String() }

func (a *fakeAgent) requestCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.reqs)
}

func (a *fakeAgent) requests() [][]byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([][]byte, len(a.reqs))
	for i := range a.reqs {
		out[i] = append([]byte(nil), a.reqs[i]...)
	}
	return out
}

// v2cResponse marshals a v2c GetResponse with the given varbinds. RequestID is
// left zero, which gosnmp accepts.
func v2cResponse(err gosnmp.SNMPError, vars ...gosnmp.SnmpPDU) []byte {
	pkt := &gosnmp.SnmpPacket{
		Version:   gosnmp.Version2c,
		Community: "public",
		PDUType:   gosnmp.GetResponse,
		Error:     err,
		Variables: vars,
	}
	b, e := pkt.MarshalMsg()
	if e != nil {
		panic(e)
	}
	return b
}

func pdu(oid string, typ gosnmp.Asn1BER, val any) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{Name: oid, Type: typ, Value: val}
}

// decodeRequest parses a raw client request for assertions.
func decodeRequest(b []byte) *gosnmp.SnmpPacket {
	g := &gosnmp.GoSNMP{Logger: gosnmp.NewLogger(log.New(io.Discard, "", 0))}
	pkt, err := g.SnmpDecodePacket(b)
	if err != nil {
		return nil
	}
	return pkt
}
