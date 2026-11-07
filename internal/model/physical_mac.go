package model

import "bytes"

// PhysicalInterfaceByMAC excludes logical interfaces which may deliberately
// reuse a member's MAC. Two physical matches remain ambiguous.
func PhysicalInterfaceByMAC(ifaces []Interface, mac []byte) (int, bool) {
	if len(mac) == 0 {
		return 0, false
	}
	idx := -1
	for i := range ifaces {
		if ifaces[i].Type == 6 && ifaces[i].IfIndex > 0 && bytes.Equal(ifaces[i].PhysAddress, mac) {
			if idx != -1 {
				return 0, false
			}
			idx = i
		}
	}
	return idx, idx != -1
}
