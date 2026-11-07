package snmp

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

func newV2Session(t *testing.T, a *fakeAgent) *Session {
	t.Helper()
	host, portStr, err := net.SplitHostPort(a.addr())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSession(context.Background(), Params{
		Target:         host,
		Port:           uint16(port),
		Timeout:        time.Second,
		Retries:        1,
		MaxRepetitions: 20,
		MaxPDUs:        500,
		Version:        "2c",
		Community:      "public",
	})
	if err != nil {
		t.Fatalf("NewSession(v2c) error = %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestNewSessionV2c(t *testing.T) {
	s := newV2Session(t, startFakeAgent(t, false))
	if s.g.Version != gosnmp.Version2c {
		t.Errorf("version = %v, want Version2c", s.g.Version)
	}
	if s.g.Community != "public" {
		t.Errorf("community = %q", s.g.Community)
	}
	// The gosnmp Logger is wired to io.Discard inside NewSession so that PDU and
	// credential data is never written; see TestGetTimeoutRetriesAndNoLeak for
	// the no-credential-in-error assertion.
}

func TestNewSessionV3(t *testing.T) {
	a := startFakeAgent(t, false)
	host, portStr, _ := net.SplitHostPort(a.addr())
	port, _ := strconv.Atoi(portStr)
	s, err := NewSession(context.Background(), Params{
		Target:         host,
		Port:           uint16(port),
		Timeout:        time.Second,
		Retries:        1,
		MaxRepetitions: 20,
		MaxPDUs:        500,
		Version:        "3",
		V3: &V3Params{
			SecurityLevel:  "authPriv",
			Username:       "user",
			AuthProtocol:   "SHA256",
			AuthPassphrase: "authpw",
			PrivProtocol:   "AES",
			PrivPassphrase: "privpw",
			ContextName:    "",
		},
	})
	if err != nil {
		t.Fatalf("NewSession(v3) error = %v", err)
	}
	defer s.Close()
	if s.g.Version != gosnmp.Version3 {
		t.Errorf("version = %v, want Version3", s.g.Version)
	}
	if s.g.MsgFlags&gosnmp.AuthPriv != gosnmp.AuthPriv {
		t.Errorf("msgflags = %v, want AuthPriv (low bits)", s.g.MsgFlags)
	}
	sp, ok := s.g.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if !ok {
		t.Fatalf("security parameters type = %T", s.g.SecurityParameters)
	}
	if sp.UserName != "user" || sp.AuthenticationProtocol != gosnmp.SHA256 || sp.PrivacyProtocol != gosnmp.AES {
		t.Errorf("unexpected v3 params: %+v", sp)
	}
}

func TestNewSessionBadVersion(t *testing.T) {
	if _, err := NewSession(context.Background(), Params{Target: "x", Version: "1"}); err == nil {
		t.Fatal("NewSession(version 1) should fail")
	}
}

func TestProtocolMaps(t *testing.T) {
	a, err := authProtocol("SHA256")
	if err != nil || a != gosnmp.SHA256 {
		t.Errorf("authProtocol(SHA256) = %v, %v", a, err)
	}
	if _, err := authProtocol("BOGUS"); err == nil {
		t.Error("authProtocol(BOGUS) should fail")
	}
	p, err := privProtocol("AES")
	if err != nil || p != gosnmp.AES {
		t.Errorf("privProtocol(AES) = %v, %v", p, err)
	}
}
