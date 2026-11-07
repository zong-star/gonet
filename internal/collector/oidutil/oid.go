// Package oidutil provides numeric OID parsing and comparison. Index handling
// must compare numeric segments, never string prefixes (section 3.3).
package oidutil

import (
	"fmt"
	"strconv"
	"strings"
)

// Split parses a numeric OID (optionally leading dot) into sub-identifiers.
func Split(oid string) ([]uint32, error) {
	s := strings.TrimPrefix(oid, ".")
	if s == "" {
		return nil, fmt.Errorf("empty OID")
	}
	parts := strings.Split(s, ".")
	out := make([]uint32, len(parts))
	for i, p := range parts {
		if p == "" {
			return nil, fmt.Errorf("invalid OID %q: empty segment", oid)
		}
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid OID %q: segment %q: %w", oid, p, err)
		}
		out[i] = uint32(v)
	}
	return out, nil
}

// Compare compares two OIDs component-wise as unsigned integers. Returns -1,
// 0 or 1. A shorter OID that is a prefix of the other is considered less.
func Compare(a, b string) int {
	aa, errA := Split(a)
	bb, errB := Split(b)
	if errA != nil || errB != nil {
		// Fall back to a stable ordering on error; callers validate OIDs.
		return strings.Compare(a, b)
	}
	n := len(aa)
	if len(bb) < n {
		n = len(bb)
	}
	for i := 0; i < n; i++ {
		if aa[i] < bb[i] {
			return -1
		}
		if aa[i] > bb[i] {
			return 1
		}
	}
	switch {
	case len(aa) < len(bb):
		return -1
	case len(aa) > len(bb):
		return 1
	default:
		return 0
	}
}

// Suffix returns the sub-identifiers of oid after base. It errors unless oid
// is strictly longer than base and shares every base segment.
func Suffix(base, oid string) ([]uint32, error) {
	b, err := Split(base)
	if err != nil {
		return nil, err
	}
	o, err := Split(oid)
	if err != nil {
		return nil, err
	}
	if len(o) <= len(b) {
		return nil, fmt.Errorf("OID %q is not below base %q", oid, base)
	}
	for i := range b {
		if b[i] != o[i] {
			return nil, fmt.Errorf("OID %q is not below base %q", oid, base)
		}
	}
	return o[len(b):], nil
}
