package snmp

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

const walkRoot = "1.3.6.1.4.1.99999.1"

func newTestSession(t *testing.T, a *fakeAgent, retries, maxPDUs int) *Session {
	t.Helper()
	host, portStr, err := net.SplitHostPort(a.addr())
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", a.addr(), err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSession(context.Background(), Params{
		Target:         host,
		Port:           uint16(port),
		Timeout:        300 * time.Millisecond,
		Retries:        retries,
		MaxRepetitions: 20,
		MaxPDUs:        maxPDUs,
		Version:        "2c",
		Community:      "public",
	})
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func collectPDUs(t *testing.T, s *Session, root string) ([]gosnmp.SnmpPDU, WalkSummary, error) {
	t.Helper()
	var pdus []gosnmp.SnmpPDU
	sum, err := s.Walk(context.Background(), root, func(p gosnmp.SnmpPDU) error {
		pdus = append(pdus, p)
		return nil
	})
	return pdus, sum, err
}

// C06: TooBig degrades max-repetitions 20→10→5→1 then GETNEXT.
func TestWalkTooBigDegrades(t *testing.T) {
	row1 := pdu(walkRoot+".1.1", gosnmp.Integer, 10)
	row2 := pdu(walkRoot+".1.2", gosnmp.Integer, 20)
	a := startFakeAgent(t, true,
		v2cResponse(gosnmp.TooBig),
		v2cResponse(gosnmp.TooBig),
		v2cResponse(gosnmp.TooBig),
		v2cResponse(gosnmp.TooBig),
		v2cResponse(gosnmp.NoError, row1),
		v2cResponse(gosnmp.NoError, row2),
		v2cResponse(gosnmp.NoError, pdu(walkRoot+".2.0", gosnmp.EndOfMibView, nil)),
	)
	s := newTestSession(t, a, 0, 100)
	pdus, sum, err := collectPDUs(t, s, walkRoot)
	if err != nil {
		t.Fatalf("Walk() error = %v", err)
	}
	if sum.Rows != 2 || len(pdus) != 2 {
		t.Fatalf("rows = %d (%d pdus), want 2", sum.Rows, len(pdus))
	}
	if sum.Requests != 7 {
		t.Fatalf("requests = %d, want 7", sum.Requests)
	}
	reqs := a.requests()
	for i, want := range []uint32{20, 10, 5, 1} {
		pkt := decodeRequest(reqs[i])
		if pkt == nil || pkt.PDUType != gosnmp.GetBulkRequest || pkt.MaxRepetitions != want {
			t.Errorf("request %d: type=%v maxReps=%d, want GetBulk %d", i, pkt.PDUType, pkt.MaxRepetitions, want)
		}
	}
	if pkt := decodeRequest(reqs[4]); pkt == nil || pkt.PDUType != gosnmp.GetNextRequest {
		t.Errorf("request 4: want GetNextRequest, got %+v", pkt)
	}
}

// C06: duplicate/non-increasing OID aborts the walk.
func TestWalkNonIncreasingAborts(t *testing.T) {
	row1 := pdu(walkRoot+".1.1", gosnmp.Integer, 10)
	a := startFakeAgent(t, true,
		v2cResponse(gosnmp.NoError, row1, row1), // duplicate OID in one bulk response
	)
	s := newTestSession(t, a, 0, 100)
	_, _, err := collectPDUs(t, s, walkRoot)
	if err == nil || !IsCode(err, CodeNonIncreasing) {
		t.Fatalf("Walk() error = %v, want CodeNonIncreasing", err)
	}
}

// C06: PDU budget is enforced.
func TestWalkPDUBudget(t *testing.T) {
	a := startFakeAgent(t, true,
		v2cResponse(gosnmp.NoError, pdu(walkRoot+".1.1", gosnmp.Integer, 10)),
	)
	s := newTestSession(t, a, 0, 1)
	_, sum, err := collectPDUs(t, s, walkRoot)
	if err == nil || !IsCode(err, CodeLimit) {
		t.Fatalf("Walk() error = %v, want CodeLimit", err)
	}
	if sum.Requests != 1 {
		t.Fatalf("requests = %d, want 1", sum.Requests)
	}
}

// C06: timeout retries within the configured budget and maps to SNMP_TIMEOUT,
// and no credential ever appears in the error text.
func TestGetTimeoutRetriesAndNoLeak(t *testing.T) {
	a := startFakeAgent(t, false) // black hole: reads and drops
	s := newTestSession(t, a, 1, 100)
	_, err := s.Get(context.Background(), []string{"1.3.6.1.2.1.1.2.0"})
	if err == nil || !IsCode(err, CodeTimeout) {
		t.Fatalf("Get() error = %v, want CodeTimeout", err)
	}
	if a.requestCount() != 2 {
		t.Fatalf("request count = %d, want 2 (1 retry)", a.requestCount())
	}
	if got := err.Error(); strings.Contains(got, "secretcomm") || strings.Contains(got, "public") {
		t.Fatalf("error leaked credential: %q", got)
	}
}

// C06: auth errors map to SNMP_AUTH and are not retried by our layer.
func TestMapErrAuth(t *testing.T) {
	for _, in := range []error{
		gosnmp.ErrUnknownUsername,
		gosnmp.ErrWrongDigest,
		gosnmp.ErrUnknownSecurityLevel,
		gosnmp.ErrDecryption,
	} {
		if !IsCode(mapErr(in), CodeAuth) {
			t.Errorf("mapErr(%v) = %v, want CodeAuth", in, mapErr(in))
		}
	}
}

func TestMapErrTimeout(t *testing.T) {
	if !IsCode(mapErr(errors.New("request timeout (after 1 retries)")), CodeTimeout) {
		t.Errorf("mapErr(timeout) not CodeTimeout")
	}
	if !IsCode(mapErr(context.DeadlineExceeded), CodeTimeout) {
		t.Errorf("mapErr(DeadlineExceeded) not CodeTimeout")
	}
}

func TestMapErrCanceled(t *testing.T) {
	if !IsCode(mapErr(context.Canceled), CodeCanceled) {
		t.Errorf("mapErr(Canceled) not CodeCanceled")
	}
}

func TestScalarGETAndRetryConsumePDUBudget(t *testing.T) {
	a := startFakeAgent(t, false)
	s := newTestSession(t, a, 2, 1)
	_, err := s.Get(context.Background(), []string{"1.3.6.1.2.1.1.2.0"})
	if err == nil || !IsCode(err, CodeLimit) || s.PDUsUsed() != 1 || a.requestCount() != 1 {
		t.Fatalf("budget: err=%v used=%d requests=%d", err, s.PDUsUsed(), a.requestCount())
	}
}
