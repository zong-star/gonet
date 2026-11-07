package discovery

import (
	"context"
	"errors"
	"testing"

	"gonet/internal/collector/snmp"
)

func TestVerificationPreservesSNMPErrorCodes(t *testing.T) {
	for _, code := range []snmp.Code{snmp.CodeTimeout, snmp.CodeAuth, snmp.CodeCanceled} {
		err := &snmp.Error{Code: code, Err: errors.New("test transport failure")}
		if got := issueFromErr("verification", err); got.Code != string(code) {
			t.Fatalf("%s reduced to %s", code, got.Code)
		}
	}
	if got := issueFromErr("verification", context.DeadlineExceeded); got.Code != "SNMP_TIMEOUT" || !got.Retryable {
		t.Fatalf("deadline lost: %+v", got)
	}
}
