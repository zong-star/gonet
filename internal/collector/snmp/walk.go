package snmp

import (
	"context"
	"fmt"

	"github.com/gosnmp/gosnmp"

	"gonet/internal/collector/oidutil"
)

// WalkSummary describes how a walk terminated.
type WalkSummary struct {
	Rows           int  // number of varbinds delivered to the callback
	Requests       int  // number of SNMP request PDUs issued
	FirstEndOfView bool // first varbind of the first request was EOMV/NoSuch*
}

// Walk traverses a table subtree with GETBULK, degrading max-repetitions on
// TooBig (20→10→5→1) then falling back to GETNEXT. It enforces the PDU budget,
// aborts on non-increasing or duplicate OIDs, and returns summary + coded error.
func (s *Session) Walk(ctx context.Context, root string, cb func(gosnmp.SnmpPDU) error) (WalkSummary, error) {
	s.g.Context = ctx
	reps := int(s.maxRepetitions)
	sum := WalkSummary{}
	prev := root

	for {
		if err := ctx.Err(); err != nil {
			return sum, mapErr(err)
		}
		if s.maxPDUs > 0 && s.pdusUsed >= s.maxPDUs {
			return sum, newError(CodeLimit, fmt.Errorf("PDU budget %d exceeded", s.maxPDUs))
		}

		var pkt *gosnmp.SnmpPacket
		var err error
		if reps > 0 {
			pkt, err = s.g.GetBulk([]string{prev}, 0, uint32(reps))
		} else {
			pkt, err = s.g.GetNext([]string{prev})
		}
		sum.Requests++

		if err != nil {
			return sum, mapErr(err)
		}
		if pkt.Error == gosnmp.TooBig {
			if reps == 0 {
				return sum, newError(CodeLimit, fmt.Errorf("TooBig persists with GETNEXT"))
			}
			reps = degrade(reps)
			continue
		}
		if pkt.Error != gosnmp.NoError {
			return sum, mapErr(fmt.Errorf("SNMP error status %v", pkt.Error))
		}

		vars := pkt.Variables
		if len(vars) == 0 {
			return sum, newError(CodeOther, fmt.Errorf("empty response without end-of-view marker"))
		}
		for i, pdu := range vars {
			if pdu.Type == gosnmp.EndOfMibView || pdu.Type == gosnmp.NoSuchObject || pdu.Type == gosnmp.NoSuchInstance {
				if sum.Rows == 0 && sum.Requests == 1 && i == 0 {
					sum.FirstEndOfView = true
				}
				return sum, nil
			}
			if _, err := oidutil.Suffix(root, pdu.Name); err != nil {
				// Out of the requested subtree: normal end.
				return sum, nil
			}
			if oidutil.Compare(prev, pdu.Name) >= 0 {
				return sum, newError(CodeNonIncreasing, fmt.Errorf("OID not increasing: %s >= %s", prev, pdu.Name))
			}
			sum.Rows++
			if err := cb(pdu); err != nil {
				return sum, err
			}
			prev = pdu.Name
		}
	}
}

// degrade steps the max-repetitions down on TooBig, returning 0 to signal the
// GETNEXT fallback.
func degrade(reps int) int {
	switch reps {
	case 20:
		return 10
	case 10:
		return 5
	case 5:
		return 1
	default:
		return 0
	}
}
