// Package snmp wraps gosnmp with a bounded walk (GETBULK with tooBig fallback,
// PDU budget) and injectable transport. It maps transport failures to stable
// error codes so the collector can record them without leaking credentials.
package snmp

import (
	"context"
	"errors"
	"strings"

	"github.com/gosnmp/gosnmp"
)

// Code is a stable, log-safe error code (section 11.2).
type Code string

const (
	CodeTimeout       Code = "SNMP_TIMEOUT"
	CodeAuth          Code = "SNMP_AUTH"
	CodeNonIncreasing Code = "WALK_NONINCREASING"
	CodeLimit         Code = "WALK_LIMIT"
	CodeUnsupported   Code = "MIB_UNSUPPORTED"
	CodeCanceled      Code = "CANCELED"
	CodeOther         Code = "SNMP_ERROR"
)

// Error is a transport-level error carrying a stable code.
type Error struct {
	Code Code
	Err  error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return string(e.Code)
	}
	return string(e.Code) + ": " + e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

func newError(code Code, err error) error {
	return &Error{Code: code, Err: err}
}

// IsCode reports whether err (or any wrapped error) carries the given code.
func IsCode(err error, code Code) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}

// mapErr converts a gosnmp/net error into a coded Error. Auth and cancellation
// are never blindly retried; timeouts keep the wording "timeout" (section 3.5).
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return newError(CodeCanceled, err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return newError(CodeTimeout, err)
	}
	msg := err.Error()
	switch {
	case IsCode(err, CodeLimit) || strings.Contains(msg, "PDU budget exceeded"):
		return newError(CodeLimit, errors.New("PDU budget exceeded"))
	case errors.Is(err, gosnmp.ErrUnknownUsername),
		errors.Is(err, gosnmp.ErrWrongDigest),
		errors.Is(err, gosnmp.ErrUnknownSecurityLevel),
		errors.Is(err, gosnmp.ErrDecryption),
		errors.Is(err, gosnmp.ErrUnknownSecurityModels),
		errors.Is(err, gosnmp.ErrNotInTimeWindow),
		errors.Is(err, gosnmp.ErrUnknownEngineID):
		return newError(CodeAuth, err)
	case strings.Contains(msg, "OID not increasing") || strings.Contains(msg, "not increasing"):
		return newError(CodeNonIncreasing, err)
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline"):
		return newError(CodeTimeout, err)
	default:
		return newError(CodeOther, err)
	}
}
