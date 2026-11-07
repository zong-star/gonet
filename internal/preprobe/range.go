// Package preprobe builds positive SNMP access evidence independently of topology.
package preprobe

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
)

type interval struct{ lo, hi uint64 }

// Range stores disjoint IPv4 intervals, never an expanded list of hosts.
type Range struct {
	spans  []interval
	Count  uint64
	Digest string
}

func ipNumber(a netip.Addr) uint64 { b := a.As4(); return uint64(binary.BigEndian.Uint32(b[:])) }
func numberIP(n uint64) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(n))
	return netip.AddrFrom4(b)
}

func prefixSpan(p netip.Prefix, hosts bool) interval {
	p = p.Masked()
	lo := ipNumber(p.Addr())
	hi := lo + (uint64(1) << (32 - p.Bits())) - 1
	if hosts && p.Bits() < 31 {
		lo++
		hi--
	}
	return interval{lo, hi}
}

// NewRange applies host rules per allowed subnet, then subtracts exclusions.
// IPv6 remains available to ordinary discovery but is never enumerated here.
func NewRange(allowed, excluded []netip.Prefix, allowLinkLocal bool) *Range {
	var spans []interval
	for _, p := range allowed {
		if p.Addr().Is4() {
			spans = append(spans, prefixSpan(p, true))
		}
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].lo < spans[j].lo })
	var merged []interval
	for _, s := range spans {
		if len(merged) > 0 && s.lo <= merged[len(merged)-1].hi+1 {
			if s.hi > merged[len(merged)-1].hi {
				merged[len(merged)-1].hi = s.hi
			}
		} else {
			merged = append(merged, s)
		}
	}
	// Preserve the existing invalid-host and IPv4 link-local policy.
	denied := []string{"0.0.0.0/32", "127.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32"}
	if !allowLinkLocal {
		denied = append(denied, "169.254.0.0/16")
	}
	for _, s := range denied {
		excluded = append(append([]netip.Prefix(nil), excluded...), netip.MustParsePrefix(s))
	}
	for _, p := range excluded {
		if !p.Addr().Is4() {
			continue
		}
		cut := prefixSpan(p, false)
		var next []interval
		for _, s := range merged {
			if cut.hi < s.lo || cut.lo > s.hi {
				next = append(next, s)
				continue
			}
			if cut.lo > s.lo {
				next = append(next, interval{s.lo, cut.lo - 1})
			}
			if cut.hi < s.hi {
				next = append(next, interval{cut.hi + 1, s.hi})
			}
		}
		merged = next
	}
	r := &Range{spans: merged}
	h := sha256.New()
	for _, s := range merged {
		r.Count += s.hi - s.lo + 1
		fmt.Fprintf(h, "%d:%d;", s.lo, s.hi)
	}
	r.Digest = fmt.Sprintf("%x", h.Sum(nil))
	return r
}

func (r *Range) At(offset uint64) (netip.Addr, bool) {
	for _, s := range r.spans {
		n := s.hi - s.lo + 1
		if offset < n {
			return numberIP(s.lo + offset), true
		}
		offset -= n
	}
	return netip.Addr{}, false
}
func (r *Range) Contains(a netip.Addr) bool {
	a = a.Unmap()
	if !a.Is4() {
		return false
	}
	n := ipNumber(a)
	i := sort.Search(len(r.spans), func(i int) bool { return r.spans[i].hi >= n })
	return i < len(r.spans) && r.spans[i].lo <= n
}
