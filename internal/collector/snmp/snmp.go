package snmp

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// Params configures one device session. Secret material is passed directly
// (already expanded from the environment) and is never logged.
type Params struct {
	Target         string
	Port           uint16
	Timeout        time.Duration
	Retries        int
	MaxRepetitions uint32
	MaxPDUs        int
	Version        string // "2c" or "3"
	Community      string
	V3             *V3Params
	Conn           net.Conn // optional injectable transport (tests)
}

// V3Params holds USM credentials for SNMPv3.
type V3Params struct {
	SecurityLevel  string // noAuthNoPriv | authNoPriv | authPriv
	Username       string
	AuthProtocol   string // MD5, SHA, SHA224, SHA256, SHA384, SHA512
	AuthPassphrase string
	PrivProtocol   string // DES, AES, AES192, AES256, AES192C, AES256C
	PrivPassphrase string
	ContextName    string
}

// Session wraps one gosnmp.GoSNMP connection and enforces the PDU budget.
// It is not safe for concurrent use.
type Session struct {
	g              *gosnmp.GoSNMP
	maxRepetitions uint32
	maxPDUs        int
	pdusUsed       int
}

// NewSession builds and connects a session (or uses the injected transport).
func NewSession(ctx context.Context, p Params) (*Session, error) {
	if p.Target == "" {
		return nil, fmt.Errorf("SNMP_ERROR: empty target")
	}
	if p.MaxRepetitions == 0 {
		p.MaxRepetitions = 20
	}
	g := &gosnmp.GoSNMP{
		Target:             p.Target,
		Port:               p.Port,
		Timeout:            p.Timeout,
		Retries:            p.Retries,
		Context:            ctx,
		MaxRepetitions:     p.MaxRepetitions,
		MaxOids:            gosnmp.MaxOids,
		Logger:             gosnmp.NewLogger(log.New(io.Discard, "", 0)),
		ExponentialTimeout: false,
	}
	switch p.Version {
	case "3":
		if p.V3 == nil {
			return nil, fmt.Errorf("SNMP_ERROR: v3 profile missing credentials")
		}
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		g.MsgFlags = v3Flags(p.V3.SecurityLevel)
		auth, err := authProtocol(p.V3.AuthProtocol)
		if err != nil {
			return nil, err
		}
		priv, err := privProtocol(p.V3.PrivProtocol)
		if err != nil {
			return nil, err
		}
		g.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 p.V3.Username,
			AuthenticationProtocol:   auth,
			AuthenticationPassphrase: p.V3.AuthPassphrase,
			PrivacyProtocol:          priv,
			PrivacyPassphrase:        p.V3.PrivPassphrase,
		}
		g.ContextName = p.V3.ContextName
	case "2c":
		g.Version = gosnmp.Version2c
		g.Community = p.Community
	default:
		return nil, fmt.Errorf("SNMP_ERROR: unsupported SNMP version %q", p.Version)
	}

	if p.Conn != nil {
		g.Conn = p.Conn
	} else if err := g.Connect(); err != nil {
		return nil, mapErr(err)
	}
	s := &Session{g: g, maxRepetitions: p.MaxRepetitions, maxPDUs: p.MaxPDUs}
	g.Conn = &budgetConn{Conn: g.Conn, session: s}
	return s, nil
}

// Count every wire request, including scalar GETs and library retries.
type budgetConn struct {
	net.Conn
	session *Session
}

func (c *budgetConn) Write(b []byte) (int, error) {
	s := c.session
	if s.maxPDUs > 0 && s.pdusUsed >= s.maxPDUs {
		return 0, newError(CodeLimit, fmt.Errorf("PDU budget exceeded"))
	}
	s.pdusUsed++
	return c.Conn.Write(b)
}

func v3Flags(level string) gosnmp.SnmpV3MsgFlags {
	switch strings.ToLower(level) {
	case "authpriv":
		return gosnmp.AuthPriv
	case "authnopriv":
		return gosnmp.AuthNoPriv
	default:
		return gosnmp.NoAuthNoPriv
	}
}

func authProtocol(s string) (gosnmp.SnmpV3AuthProtocol, error) {
	switch strings.ToUpper(s) {
	case "", "NOAUTH":
		return gosnmp.NoAuth, nil
	case "MD5":
		return gosnmp.MD5, nil
	case "SHA", "SHA1":
		return gosnmp.SHA, nil
	case "SHA224":
		return gosnmp.SHA224, nil
	case "SHA256":
		return gosnmp.SHA256, nil
	case "SHA384":
		return gosnmp.SHA384, nil
	case "SHA512":
		return gosnmp.SHA512, nil
	default:
		return 0, fmt.Errorf("SNMP_ERROR: unknown auth protocol %q", s)
	}
}

func privProtocol(s string) (gosnmp.SnmpV3PrivProtocol, error) {
	switch strings.ToUpper(s) {
	case "", "NOPRIV":
		return gosnmp.NoPriv, nil
	case "DES":
		return gosnmp.DES, nil
	case "AES", "AES128":
		return gosnmp.AES, nil
	case "AES192":
		return gosnmp.AES192, nil
	case "AES256":
		return gosnmp.AES256, nil
	case "AES192C":
		return gosnmp.AES192C, nil
	case "AES256C":
		return gosnmp.AES256C, nil
	default:
		return 0, fmt.Errorf("SNMP_ERROR: unknown priv protocol %q", s)
	}
}

// Get performs a GET for a small set of scalar OIDs and returns the varbinds.
func (s *Session) Get(ctx context.Context, oids []string) ([]gosnmp.SnmpPDU, error) {
	if err := ctx.Err(); err != nil {
		return nil, mapErr(err)
	}
	s.g.Context = ctx
	pkt, err := s.g.Get(oids)
	if err != nil {
		return nil, mapErr(err)
	}
	if pkt.Error != gosnmp.NoError {
		if pkt.Error == gosnmp.AuthorizationError || pkt.Error == gosnmp.NoAccess {
			return nil, newError(CodeAuth, fmt.Errorf("SNMP authorization denied"))
		}
		return nil, mapErr(fmt.Errorf("SNMP error status %v", pkt.Error))
	}
	return pkt.Variables, nil
}

// Close closes the underlying connection (safe to call repeatedly).
func (s *Session) Close() error {
	if s.g == nil {
		return nil
	}
	return s.g.Close()
}

// PDUsUsed reports how many request PDUs were consumed so far.
func (s *Session) PDUsUsed() int { return s.pdusUsed }

// LimitAdditionalPDUs tightens the remaining wire budget for optional walks.
func (s *Session) LimitAdditionalPDUs(count int) {
	limit := s.pdusUsed + count
	if s.maxPDUs <= 0 || limit < s.maxPDUs {
		s.maxPDUs = limit
	}
}
