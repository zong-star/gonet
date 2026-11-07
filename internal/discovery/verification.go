package discovery

import (
	"net/netip"
	"time"

	"gonet/internal/identity"
	"gonet/internal/model"
	"gonet/internal/topology"
)

// Verification is an LLDP observation plus its current, independently verified
// access state. It never binds an advertised address before direct collection.
type Verification struct {
	SourceDevice  model.DevRef              `json:"source_device"`
	Neighbor      model.LLDPNeighbor        `json:"neighbor"`
	DiscoveredAt  time.Time                 `json:"discovered_at"`
	MatchedDevice model.DevRef              `json:"matched_device,omitempty"`
	Details       model.VerificationDetails `json:"verification"`
}

type verificationAttempt struct {
	Addr netip.Addr
	Err  error
	At   time.Time
}

// Event is emitted only by the coordinator, so log writers need no extra lock.
type Event struct {
	SourceDevice  model.DevRef  `json:"source_device"`
	SourcePort    uint32        `json:"source_port"`
	RemoteSysName string        `json:"remote_sys_name"`
	RemoteChassis model.TypedID `json:"remote_chassis_id"`
	ReportedIPs   []netip.Addr  `json:"reported_management_ip"`
	SelectedIP    string        `json:"selected_snmp_ip"`
	Result        string        `json:"verification_result"`
	ErrorCode     string        `json:"verification_error"`
	Error         string        `json:"error_detail,omitempty"`
	MatchedDevice model.DevRef  `json:"matched_device_ref"`
	NextAction    string        `json:"next_action"`
}

func (c *Coordinator) SetEventHandler(fn func(Event)) { c.opts.OnEvent = fn }

func (c *Coordinator) trackNeighbor(source model.DevRef, n model.LLDPNeighbor, at time.Time) {
	v := Verification{SourceDevice: source, Neighbor: n, DiscoveredAt: at}
	c.neighbors = append(c.neighbors, v)
	c.emit(v, 0, "discovered", "", "", "", "match_identity")
}

func (c *Coordinator) failVerification(ref model.DevRef, code, reason string, ip netip.Addr) {
	if ds := c.devStates[ref]; ds != nil {
		ds.Enqueued = false
		ds.Verification = "verification_failed"
		if code == "IDENTITY_CONFLICT" {
			ds.Verification = "identity_conflict"
		}
		ds.FailureCode, ds.FailureReason, ds.SelectedIP = code, reason, ip
	}
}

func (c *Coordinator) recordAttempts(r taskResult) {
	if ds := c.devStates[r.Task.Device]; ds != nil {
		ds.Enqueued = false
		ds.Attempted += len(r.Tried)
	}
	for _, a := range r.Attempts {
		if a.Err != nil {
			issue := issueFromErr("verification", a.Err)
			c.failVerification(r.Task.Device, issue.Code, issue.Message, a.Addr)
			c.emitForDevice(r.Task.Device, "verification_failed", issue.Code, issue.Message, a.Addr, "try_next_address_or_next_scan")
		}
		if ds := c.devStates[r.Task.Device]; ds != nil {
			at := a.At
			ds.VerifiedAt = &at
		}
	}
}

func (c *Coordinator) emitForDevice(ref model.DevRef, result, code, detail string, ip netip.Addr, next string) {
	if c.opts.OnEvent == nil {
		return
	}
	for _, v := range c.neighbors {
		resolved := c.opts.Registry.ResolveAdvertised(v.Neighbor)
		if resolved.Device == nil || resolved.Device.Ref != ref {
			continue
		}
		c.emit(v, ref, result, code, detail, ip.String(), next)
	}
}

func (c *Coordinator) emit(v Verification, ref model.DevRef, result, code, detail, ip, next string) {
	if c.opts.OnEvent == nil {
		return
	}
	c.opts.OnEvent(Event{SourceDevice: v.SourceDevice, SourcePort: v.Neighbor.Index.LocalPortNum,
		RemoteSysName: v.Neighbor.SysName, RemoteChassis: v.Neighbor.Chassis,
		ReportedIPs: v.Neighbor.MgmtAddresses, SelectedIP: ip, Result: result,
		ErrorCode: code, Error: detail, MatchedDevice: ref, NextAction: next})
}

func (c *Coordinator) finishVerifications() []Verification {
	out := make([]Verification, 0, len(c.neighbors))
	for _, v := range c.neighbors {
		d := model.VerificationDetails{Status: "pending", FailureCode: "NO_ACCESS_ADDRESS", FailureReason: "no usable SNMP access address"}
		class := c.opts.Registry.ClassifyNeighbor(v.Neighbor)
		res := c.opts.Registry.ResolveAdvertised(v.Neighbor)
		if class.Excluded() {
			d.Status, d.FailureCode, d.FailureReason = "excluded", "EXCLUDED_DEVICE", class.Reason
		} else if res.State == identity.ResolvedConflict {
			d.Status, d.FailureCode, d.FailureReason = "identity_conflict", "IDENTITY_CONFLICT", "chassis has conflicting owners"
		} else if res.Device != nil {
			state := c.devStates[res.Device.Ref]
			if state != nil {
				d.SelectedIP, d.LastAttemptAt = addrText(state.SelectedIP), state.VerifiedAt
				if state.Verification != "" {
					d.Status, d.FailureCode, d.FailureReason = state.Verification, state.FailureCode, state.FailureReason
				}
				if state.Collected && res.Device.State == identity.StateVerified {
					v.MatchedDevice = res.Device.Ref
					d.Status, d.FailureCode, d.FailureReason = "verified", "", ""
				}
			}
		} else {
			d.FailureCode, d.FailureReason = "IDENTITY_UNRESOLVED", "no verified chassis identity; observation retained"
		}
		if d.Status == "pending" && d.FailureCode == "NO_ACCESS_ADDRESS" {
			for _, ip := range v.Neighbor.MgmtAddresses {
				if !c.validHostAddr(ip) {
					d.FailureCode, d.FailureReason = "INVALID_MANAGEMENT_IP", "advertised address is not a routable management host"
					continue
				}
				if !c.inScope(ip) {
					d.FailureCode, d.FailureReason = "ADDRESS_OUT_OF_SCOPE", "advertised address is outside the configured scan scope"
					continue
				}
				d.FailureCode, d.FailureReason = "NOT_SCANNED_THIS_RUN", "scan budget, depth or address ownership prevented verification"
				break
			}
		}
		v.Details = d
		next := "retry_next_scan"
		if d.Status == "verified" {
			next = "scan_completed"
		}
		c.emit(v, v.MatchedDevice, d.Status, d.FailureCode, d.FailureReason, d.SelectedIP, next)
		out = append(out, v)
	}
	return out
}

func addrText(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	return ip.String()
}

// Key is scoped for opaque/missing identities and independent of management IP.
func (v Verification) Key(sourceID uint64) string { return topology.CandidateKey(v.Neighbor, sourceID) }
