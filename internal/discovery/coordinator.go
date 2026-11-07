// Package discovery implements layered BFS discovery from core seeds (M3).
// The coordinator owns all mutable state; workers only return snapshots over a
// bounded channel. T302 adds management-address policy, ordered per-device
// fallback, full budgets and branch termination reasons.
package discovery

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"gonet/internal/collector/snmp"
	"gonet/internal/identity"
	"gonet/internal/model"
	"gonet/internal/preprobe"
	"gonet/internal/topology"
)

// IP status values (section 6.2); never a single visited bool.
const (
	IPQueued    = "queued"
	IPRunning   = "running"
	IPSucceeded = "succeeded"
	IPFailed    = "failed"
)

// Device status values (section 7.1). unscanned is a reason, not success.
const (
	DevUnscanned = "unscanned"
	DevQueued    = "queued"
	DevCollected = "collected"
	DevFailed    = "failed"
)

// candidateAddr is one management address candidate for a device.
type candidateAddr struct {
	Freshness      time.Time
	Addr           netip.Addr
	Source         string // seed | lldp | manual
	Verified       bool
	ManualPriority int // explicit manual preference (lower first)
	CIDRIndex      int // management_cidrs order
}

// DeviceTask is one device's collection task with ordered candidate addresses.
type DeviceTask struct {
	Device     model.DevRef
	Depth      int
	Candidates []netip.Addr
}

// taskResult is a worker's outcome: the first succeeded snapshot plus the list
// of addresses it tried in order.
type taskResult struct {
	Task     DeviceTask
	Addr     netip.Addr
	Snapshot *model.DeviceSnapshot
	Err      error
	Tried    []netip.Addr
	Attempts []verificationAttempt
}

type ipState struct {
	Addr   netip.Addr
	Status string
	Depth  int
	Owner  model.DevRef
}

type deviceState struct {
	MissingAddressReported bool
	Ref                    model.DevRef
	Status                 string
	MinDepth               int
	Collected              bool
	Enqueued               bool
	Candidates             []candidateAddr
	Addrs                  map[netip.Addr]bool
	Attempted              int
	SelectedIP             netip.Addr
	Verification           string
	FailureCode            string
	FailureReason          string
	VerifiedAt             *time.Time
}

// Options configures a discovery run.
type Options struct {
	Preprobe              preprobe.Options
	OnProbe               func(preprobe.Attempt, preprobe.Record)
	AllowIPv4LinkLocal    bool
	Seeds                 []netip.Addr
	ManagementCIDRs       []netip.Prefix
	ExcludedCIDRs         []netip.Prefix
	MaxDepth              int
	MaxDevices            int
	MaxTargets            int
	Workers               int
	RunTimeout            time.Duration
	MaxAddressesPerDevice int
	Profile               string
	AddressOverrides      map[string][]netip.Addr
	OnProgress            func(Progress)
	OnEvent               func(Event)

	Collector model.Collector
	Registry  *identity.Registry
	Resolver  *topology.Resolver
}

// Progress is emitted by the coordinator goroutine; callbacks must not block.
type Progress struct {
	Probe     *preprobe.Summary `json:"probe,omitempty"`
	Stage     string            `json:"stage"`
	Target    string            `json:"target,omitempty"`
	Completed int               `json:"completed"`
	Scheduled int               `json:"scheduled"`
	Depth     int               `json:"depth"`
}

func (c *Coordinator) SetProgress(fn func(Progress)) { c.opts.OnProgress = fn }

// Counts are the per-run coverage counters (section 8.3 subset).
type Counts struct {
	CollectQueued          int   `json:"collect_queued"`
	CollectCompleted       int   `json:"collect_completed"`
	CollectFailed          int   `json:"collect_failed"`
	CollectPDUs            int   `json:"collect_pdus"`
	CollectElapsedMS       int64 `json:"collect_elapsed_ms"`
	AdmittedCandidates     int   `json:"admitted_candidates"`
	DevicesDiscovered      int   `json:"devices_discovered"`
	DevicesCollected       int   `json:"devices_collected"`
	DevicesFailed          int   `json:"devices_failed"`
	DevicesUnscanned       int   `json:"devices_unscanned"`
	ExcludedNeighbors      int   `json:"excluded_neighbors"`
	UnknownNeighbors       int   `json:"unknown_neighbors"`
	UnresolvedObservations int   `json:"unresolved_observations"`
	LinksObserved          int   `json:"links_observed"`
	TruncatedBranches      int   `json:"truncated_branches"`
	EligibleDevices        int   `json:"eligible_devices"`
}

// Candidate records an advertised neighbor's classification and disposition.
type Candidate struct {
	Observer       model.DevRef            `json:"observer"`
	Chassis        model.TypedID           `json:"chassis"`
	Port           model.TypedID           `json:"port"`
	SysName        string                  `json:"sys_name"`
	Classification identity.Classification `json:"classification"`
	Row            model.NeighborIndex     `json:"row"`
	Disposition    string                  `json:"disposition"` // excluded | unknown | probed
	Raw            model.LLDPNeighbor      `json:"raw"`
	At             time.Time               `json:"at"`
}

// Result is the frozen output of one discovery round.
type Result struct {
	CollectionTargets []CollectionTarget               `json:"collection_targets,omitempty"`
	Preprobe          preprobe.Batch                   `json:"preprobe"`
	Verifications     []Verification                   `json:"verifications,omitempty"`
	PendingNodes      []topology.PendingNode           `json:"pending_nodes"`
	PendingLinks      []topology.PendingLink           `json:"pending_links"`
	SchemaVersion     int                              `json:"schema_version"`
	Status            string                           `json:"status"`
	Devices           []*identity.Device               `json:"devices"`
	Ports             []*topology.Port                 `json:"ports"`
	Outcomes          []model.ScanOutcome              `json:"outcomes"`
	Observations      []model.LinkObservation          `json:"observations"`
	Unresolved        []topology.UnresolvedObservation `json:"unresolved"`
	Candidates        []Candidate                      `json:"candidates"`
	Links             []model.LinkEvidence             `json:"links"`
	Counts            Counts                           `json:"counts"`
	Issues            []model.Issue                    `json:"issues"`
	Termination       string                           `json:"termination_reason"`
}

type CollectionTarget struct {
	Device     model.DevRef `json:"device,omitempty"`
	Address    string       `json:"address"`
	Status     string       `json:"status"`
	ReasonCode string       `json:"reason_code"`
}

// Coordinator runs one layered BFS. All mutable state is owned by the caller of
// Run; workers only invoke the Collector.
type Coordinator struct {
	budget            targetBudget
	probePool         []preprobe.Record
	probeIndex        *preprobe.Index
	probeCursor       preprobe.Cursor
	probeBatch        preprobe.Batch
	probeNewTargets   int
	accessHints       map[string][]netip.Addr
	opts              Options
	ipStates          map[netip.Addr]*ipState
	devStates         map[model.DevRef]*deviceState
	links             *topology.LinkBuilder
	outcomes          []model.ScanOutcome
	observations      []model.LinkObservation
	unresolved        []topology.UnresolvedObservation
	candidates        []Candidate
	issues            []model.Issue
	counts            Counts
	status            string
	targets           int
	timedOut          bool
	budgetExhausted   bool
	progressDone      int
	progressScheduled int
	neighbors         []Verification
}

// New validates and builds a Coordinator.
func New(o Options) (*Coordinator, error) {
	if o.Collector == nil {
		return nil, fmt.Errorf("discovery: Collector is required")
	}
	if o.Registry == nil {
		return nil, fmt.Errorf("discovery: Registry is required")
	}
	if o.Workers < 1 {
		o.Workers = 1
	}
	if o.MaxDepth < 0 {
		o.MaxDepth = 0
	}
	if o.MaxDevices <= 0 {
		o.MaxDevices = 200
	}
	if o.MaxTargets <= 0 {
		o.MaxTargets = 600
	}
	if o.MaxAddressesPerDevice <= 0 {
		o.MaxAddressesPerDevice = 3
	}
	return &Coordinator{
		budget:    targetBudget{max: o.MaxTargets, addresses: map[netip.Addr]bool{}},
		opts:      o,
		ipStates:  map[netip.Addr]*ipState{},
		devStates: map[model.DevRef]*deviceState{},
		links:     topology.NewLinkBuilder(),
	}, nil
}

func (c *Coordinator) RestoreContext(devices []*identity.Device, ports []*topology.Port) error {
	if err := c.opts.Registry.Restore(devices); err != nil {
		return err
	}
	return c.opts.Resolver.Ports().Restore(ports)
}

// Run executes the layered BFS and returns the frozen result.
func (c *Coordinator) Run(ctx context.Context) *Result {
	if c.opts.RunTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.opts.RunTimeout)
		defer cancel()
	}

	c.runPreprobe(ctx)
	collectionStarted := time.Now()
	frontier := c.initSeeds()
	for depth := 0; len(frontier) > 0; depth++ {
		results := c.collectLayer(ctx, frontier)
		frontier = c.processLayer(depth, results)
		if err := ctx.Err(); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				c.timedOut = true
				c.status = "partial"
				c.issues = append(c.issues, model.Issue{Code: "RUN_TIMEOUT", Component: "discovery",
					Message: "run deadline exceeded; completed positive results retained"})
			} else {
				c.status = "aborted"
			}
			break
		}
	}
	// Keep the legacy deterministic replay JSON contract. Stage wall time is
	// telemetry of the new pipeline, not part of disabled-mode topology facts.
	if c.opts.Preprobe.Enabled {
		c.counts.CollectElapsedMS = time.Since(collectionStarted).Milliseconds()
	}
	return c.finalize()
}

func (c *Coordinator) initSeeds() []DeviceTask {
	var out []DeviceTask
	seen := map[netip.Addr]bool{}
	for _, a := range c.opts.Seeds {
		a = a.Unmap()
		if seen[a] {
			continue
		}
		seen[a] = true
		if !c.validHostAddr(a) {
			c.terminate(a, "ADDRESS_INVALID", "seed is not a valid management host address")
			continue
		}
		if !c.inScope(a) {
			c.terminate(a, "ADDRESS_OUT_OF_SCOPE", "seed outside management_cidrs")
			continue
		}
		if len(out) >= c.opts.MaxDevices {
			c.terminate(a, "DEVICE_LIMIT", "max_devices reached before admitting seed")
			continue
		}
		if !c.reserveTarget(a) {
			c.terminate(a, "TARGET_LIMIT", "max_targets reached before admitting seed")
			continue
		}
		c.ipStates[a] = &ipState{Addr: a, Status: IPQueued, Depth: 0}
		out = append(out, DeviceTask{Depth: 0, Candidates: []netip.Addr{a}})
	}
	return out
}

// collectLayer dispatches the current layer through a bounded worker pool. The
// coordinator marks state; workers never touch shared maps.
func (c *Coordinator) collectLayer(ctx context.Context, tasks []DeviceTask) []taskResult {
	stage := "core_collection"
	if tasks[0].Depth > 0 {
		stage = "recursive_collection"
	}
	for _, t := range tasks {
		c.counts.CollectQueued += len(t.Candidates)
	}
	c.progressScheduled += len(tasks)
	if c.opts.OnProgress != nil {
		c.opts.OnProgress(Progress{Stage: stage, Completed: c.progressDone, Scheduled: c.progressScheduled, Depth: tasks[0].Depth})
	}
	for _, t := range tasks {
		for _, a := range t.Candidates {
			if st := c.ipStates[a]; st != nil {
				st.Status = IPRunning
			}
		}
		if len(t.Candidates) > 0 {
			c.emitForDevice(t.Device, "verifying", "", "", t.Candidates[0], "snmp_collect")
		}
	}
	resultCh := make(chan taskResult, len(tasks))
	sem := make(chan struct{}, c.opts.Workers)
	var wg sync.WaitGroup

	go func() {
	launch:
		for _, t := range tasks {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				break launch
			}
			wg.Add(1)
			go func(t DeviceTask) {
				defer wg.Done()
				defer func() { <-sem }()
				resultCh <- c.runTask(ctx, t)
			}(t)
		}
		wg.Wait()
		close(resultCh)
	}()

	out := make([]taskResult, 0, len(tasks))
	for r := range resultCh {
		out = append(out, r)
		c.progressDone++
		if c.opts.OnProgress != nil {
			target := ""
			if r.Addr.IsValid() {
				target = r.Addr.String()
			}
			c.opts.OnProgress(Progress{Stage: stage, Target: target, Completed: c.progressDone, Scheduled: c.progressScheduled, Depth: r.Task.Depth})
		}
	}
	sort.Slice(out, func(i, j int) bool { return lessTaskResult(out[i], out[j]) })
	return out
}

// runTask tries the device's candidate addresses in order and returns the first
// snapshot. It only reads immutable options, so workers are race-free.
func (c *Coordinator) runTask(ctx context.Context, t DeviceTask) taskResult {
	var tried []netip.Addr
	var attempts []verificationAttempt
	var lastErr error
	for _, a := range t.Candidates {
		if err := ctx.Err(); err != nil {
			lastErr = err
			break
		}
		tried = append(tried, a)
		snap, err := c.opts.Collector.Collect(ctx, model.DiscoveryTarget{
			Address: a, Depth: t.Depth, Profile: c.opts.Profile,
		})
		attempts = append(attempts, verificationAttempt{Addr: a, Err: err, At: time.Now().UTC()})
		if snap != nil {
			return taskResult{Task: t, Addr: a, Snapshot: snap, Err: err, Tried: tried, Attempts: attempts}
		}
		lastErr = err
	}
	return taskResult{Task: t, Err: lastErr, Tried: tried, Attempts: attempts}
}

// processLayer resolves collected snapshots and returns the next layer.
func (c *Coordinator) processLayer(depth int, results []taskResult) []DeviceTask {
	for _, r := range results {
		c.markAttempts(r)
		c.recordAttempts(r)
		c.counts.CollectCompleted += len(r.Tried)
		c.counts.CollectFailed += len(r.Tried)
		if r.Snapshot != nil {
			c.counts.CollectFailed--
			c.counts.CollectPDUs += r.Snapshot.RequestPDUs
		}
		if r.Snapshot == nil {
			if r.Task.Device != 0 {
				if ds := c.devState(r.Task.Device); ds != nil {
					ds.Status = DevFailed
					ds.Enqueued = false
				}
			}
			c.counts.DevicesFailed++
			c.status = "partial"
			if r.Err != nil {
				c.issues = append(c.issues, issueFromErr("collect", r.Err))
			}
			continue
		}

		if !c.verifyProbeSnapshot(r) {
			continue
		}
		c.issues = append(c.issues, r.Snapshot.Issues...)
		if r.Err != nil {
			c.issues = append(c.issues, issueFromErr("collect", r.Err))
		}
		if r.Task.Device != 0 && !c.opts.Registry.Matches(r.Task.Device, r.Snapshot.Device.Chassis) {
			c.failVerification(r.Task.Device, "IDENTITY_CONFLICT", "SNMP chassis does not match LLDP advertisement", r.Addr)
			c.status = "partial"
			if r.Snapshot.Device.Chassis.Subtype == 0 || len(r.Snapshot.Device.Chassis.Raw) == 0 {
				c.failVerification(r.Task.Device, "LLDP_LOCAL_UNAVAILABLE", "local LLDP chassis is unavailable", r.Addr)
				c.issues = append(c.issues, model.Issue{Code: "LLDP_LOCAL_UNAVAILABLE", Component: "identity",
					Message: "local LLDP chassis is unreadable; advertised identity cannot be verified, address not bound"})
				continue
			}
			if _, bound := c.opts.Registry.ByAddr(r.Addr); bound {
				conflict := c.opts.Registry.ResolveDirect(r.Snapshot)
				c.issues = append(c.issues, conflict.Issues...)
			}
			c.issues = append(c.issues, model.Issue{Code: "IDENTITY_CONFLICT", Component: "discovery", Message: "direct chassis does not match advertised identity; candidate address not bound"})
			continue
		}
		res := c.opts.Registry.ResolveDirect(r.Snapshot)
		c.issues = append(c.issues, res.Issues...)
		if res.Device == nil {
			c.status = "partial"
			continue
		}
		dev := res.Device
		if res.State == identity.ResolvedConflict || dev.State == identity.StateConflict {
			c.failVerification(r.Task.Device, "IDENTITY_CONFLICT", "address and chassis evidence conflict", r.Addr)
			c.status = "partial"
			continue
		}
		if r.Task.Device != 0 && r.Task.Device != dev.Ref {
			c.status = "partial"
			c.issues = append(c.issues, model.Issue{Code: "IDENTITY_MISMATCH", Component: "discovery",
				Message: fmt.Sprintf("address %s expected device %d but resolved device %d", r.Addr, r.Task.Device, dev.Ref)})
			continue
		}
		// ResolveDirect verifies identity; the coordinator knows which access
		// evidence actually scheduled this address and records that provenance.
		source := "seed"
		if state := c.devStates[r.Task.Device]; state != nil {
			for _, candidate := range state.Candidates {
				if candidate.Addr == r.Addr {
					source = candidate.Source
					break
				}
			}
		}
		for i := range dev.Addresses {
			if dev.Addresses[i].Addr == r.Addr && dev.Addresses[i].State == identity.AddrVerified {
				dev.Addresses[i].Source = source
			}
		}
		if dev.SysName != "" {
			for _, other := range c.opts.Registry.Devices() {
				if other.Ref != dev.Ref && other.State == identity.StateVerified && other.SysName == dev.SysName && other.StrongKey != dev.StrongKey {
					c.issues = append(c.issues, model.Issue{Code: "SYSNAME_CONFLICT", Component: "identity", Message: fmt.Sprintf("devices %d and %d advertise the same name; distinct verified chassis retained", other.Ref, dev.Ref)})
				}
			}
		}

		// A probed device needs a supported managed kind and strong identity.
		if !dev.Classification.Managed() || dev.StrongKey == "" {
			c.failVerification(r.Task.Device, "UNKNOWN_DEVICE", "SNMP identity or supported device kind is not confirmed", r.Addr)
			if dev.Classification.Excluded() {
				// Explicitly excluded: no recursion, no partial.
				continue
			}
			c.status = "partial"
			c.issues = append(c.issues, model.Issue{Code: "UNKNOWN_DEVICE", Component: "discovery",
				Message: fmt.Sprintf("device %d (%s) remains unclassified; branch terminated", dev.Ref, dev.SysName)})
			continue
		}

		ds := c.devState(dev.Ref)
		if ds == nil {
			continue
		}
		ds.Enqueued = false
		ds.SelectedIP = r.Addr
		ds.Verification = "verified"
		ds.FailureCode, ds.FailureReason = "", ""
		verifiedAt := r.Snapshot.CollectedAt
		if verifiedAt.IsZero() {
			verifiedAt = time.Now().UTC()
		}
		ds.VerifiedAt = &verifiedAt
		if !ds.Collected {
			if ds.MissingAddressReported {
				ds.MissingAddressReported = false
				c.counts.DevicesUnscanned--
			}
			ds.Collected = true
			ds.Status = DevCollected
			c.counts.DevicesCollected++
		}
		if !r.Snapshot.CollectionComplete || !r.Snapshot.SnapshotStable || r.Err != nil {
			c.status = "partial"
		}
		if r.Task.Depth < ds.MinDepth {
			ds.MinDepth = r.Task.Depth
		}
		c.outcomes = append(c.outcomes, model.ScanOutcome{
			Device:   dev.Ref,
			Target:   model.DiscoveryTarget{Address: r.Addr, Depth: r.Task.Depth},
			Snapshot: r.Snapshot,
			Issues:   append([]model.Issue(nil), r.Snapshot.Issues...),
		})

		localByNum := map[uint32]model.PortRef{}
		c.opts.Resolver.SetDeviceRule(dev.Ref, dev.Classification.RuleID)
		c.opts.Resolver.SetDeviceIdentity(dev.Ref, dev.StrongKey)
		c.opts.Resolver.SetDeviceSnapshot(dev.Ref, r.Snapshot)
		for _, lp := range r.Snapshot.LocalPorts {
			pr := c.opts.Resolver.ResolveLocalPort(dev.Ref, lp, r.Snapshot.Interfaces)
			c.issues = append(c.issues, pr.Issues...)
			if pr.State == topology.PortUnresolved || pr.State == topology.PortConflict {
				c.disableAbsence(dev.Ref)
				c.status = "partial"
			}
			if pr.Port != nil {
				localByNum[lp.Number] = pr.Port.Ref
			}
		}

		for _, n := range r.Snapshot.Neighbors {
			c.trackNeighbor(dev.Ref, n, r.Snapshot.CollectedAt)
			invalidRow := len(n.Issues) > 0
			if invalidRow {
				c.status = "partial"
				c.disableAbsence(dev.Ref)
			}
			localRef, ok := localByNum[n.Index.LocalPortNum]
			localFound := ok
			class := c.opts.Registry.ClassifyNeighbor(n)
			if class.Excluded() {
				// Explicitly excluded terminals/APs are not recursed into and do
				// not make the run partial.
				c.counts.ExcludedNeighbors++
				c.recordCandidate(dev.Ref, n, class, "excluded", r.Snapshot.CollectedAt)
				continue
			}
			unknown := class.Result == "unknown" && !class.IsProbeCandidate()
			if unknown {
				c.recordCandidate(dev.Ref, n, class, "unknown", r.Snapshot.CollectedAt)
			}
			remoteDev, ok := c.admitRemote(n)
			// Classification and identity can both be unknown for the same
			// row. Count that neighbor once, rather than once per failure.
			if unknown || (!ok && !c.opts.Registry.IsStrong(n.Chassis)) {
				c.counts.UnknownNeighbors++
			}
			if !ok {
				reason := "remote identity unresolved"
				if c.opts.Registry.ResolveAdvertised(n).State == identity.ResolvedConflict {
					reason = "identity conflict: normalized MAC has multiple owners"
				}
				c.recordUnresolved(dev.Ref, localRef, 0, n, r.Snapshot.CollectedAt, reason)
				continue
			}
			// Discovery must not depend on port resolution. The peer's own
			// snapshot may be needed to resolve the advertised typed port.
			if remoteState := c.devState(remoteDev.Ref); remoteState != nil && r.Task.Depth+1 < remoteState.MinDepth {
				remoteState.MinDepth = r.Task.Depth + 1
			}
			c.opts.Resolver.SetDeviceIdentity(remoteDev.Ref, remoteDev.StrongKey)
			c.addProbeCandidates(remoteDev)
			for _, a := range c.opts.AddressOverrides[remoteDev.StrongKey] {
				c.addCandidate(remoteDev.Ref, a, "manual", false)
			}
			// Access inventory is independent of this round's LLDP management
			// TLV. Aliases and previously verified addresses are access routes.
			for _, key := range c.opts.Registry.CandidateKeys(remoteDev) {
				for _, a := range c.opts.AddressOverrides[key] {
					c.addCandidate(remoteDev.Ref, a, "manual", false)
				}
			}
			for _, a := range remoteDev.Addresses {
				if a.State == identity.AddrVerified {
					c.addCandidate(remoteDev.Ref, a.Addr, a.Source, true)
				}
			}
			for _, a := range n.MgmtAddresses {
				c.addCandidate(remoteDev.Ref, a, "lldp", false)
			}
			if invalidRow {
				// A broken port field cannot form a link. An independently
				// resolved chassis and explicit/advertised address can still
				// authorize a bounded identity-verifying probe of the peer.
				c.recordUnresolved(dev.Ref, localRef, remoteDev.Ref, n, r.Snapshot.CollectedAt, "invalid remote identity/port row")
				continue
			}
			if !localFound {
				c.recordUnresolved(dev.Ref, 0, remoteDev.Ref, n, r.Snapshot.CollectedAt, "observer local port not found")
				continue
			}
			remoteRef, ok := c.resolveRemotePort(remoteDev.Ref, n)
			if !ok {
				c.recordUnresolved(dev.Ref, localRef, remoteDev.Ref, n, r.Snapshot.CollectedAt, "remote port unresolved")
				continue
			}
			obs := model.LinkObservation{
				Observer:   dev.Ref,
				LocalPort:  localRef,
				Remote:     remoteDev.Ref,
				RemotePort: remoteRef,
				Row:        n.Index,
				At:         r.Snapshot.CollectedAt,
				Raw:        n,
			}
			c.observations = append(c.observations, obs)
			c.links.Add(obs)
		}
	}
	return c.buildNextFrontier(depth)
}

// admitRemote resolves or admits the advertised remote device, respecting the
// max_devices budget for new devices.
func (c *Coordinator) admitRemote(n model.LLDPNeighbor) (*identity.Device, bool) {
	res := c.opts.Registry.ResolveAdvertised(n)
	c.issues = append(c.issues, res.Issues...)
	if res.State == identity.ResolvedConflict {
		c.status = "partial"
		return nil, false
	}
	if res.State == identity.Resolved && res.Device != nil {
		return res.Device, true
	}
	if !c.opts.Registry.IsStrong(n.Chassis) {
		return nil, false
	}
	if len(c.devStates) >= c.opts.MaxDevices {
		c.terminate(netip.Addr{}, "DEVICE_LIMIT", "max_devices reached while admitting advertised device")
		return nil, false
	}
	dev, ok := c.opts.Registry.EnsureAdvertised(n)
	if !ok {
		return nil, false
	}
	return dev, true
}

// buildNextFrontier admits candidates for uncollected devices, enforcing the
// depth, target and per-device address budgets.
func (c *Coordinator) buildNextFrontier(depth int) []DeviceTask {
	refs := make([]model.DevRef, 0, len(c.devStates))
	for ref := range c.devStates {
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i] < refs[j] })

	var out []DeviceTask
	for _, ref := range refs {
		ds := c.devStates[ref]
		if ds.Collected || ds.Enqueued {
			continue
		}
		if len(ds.Candidates) == 0 {
			if !ds.MissingAddressReported {
				ds.MissingAddressReported = true
				c.counts.DevicesUnscanned++
				c.status = "partial"
				c.issues = append(c.issues, model.Issue{Code: "NO_ACCESS_ADDRESS", Component: "discovery", Message: fmt.Sprintf("device %d has no configured or verified SNMP access address; neighbor evidence retained", ref)})
			}
			continue
		}
		if ds.MinDepth > c.opts.MaxDepth {
			c.terminate(netip.Addr{}, "DEPTH_LIMIT", fmt.Sprintf("device %d beyond max_depth %d", ref, c.opts.MaxDepth))
			continue
		}
		sortCandidates(ds.Candidates)
		var chosen []netip.Addr
		for _, cand := range ds.Candidates {
			if ds.Attempted+len(chosen) >= c.opts.MaxAddressesPerDevice {
				break
			}
			st := c.ipStates[cand.Addr]
			if st != nil && (st.Status != IPQueued || st.Owner != ref) {
				continue // one request sequence per IP this round
			}
			if st == nil && !c.reserveTarget(cand.Addr) {
				c.terminate(cand.Addr, "TARGET_LIMIT", fmt.Sprintf("max_targets %d reached", c.opts.MaxTargets))
				break
			}
			c.ipStates[cand.Addr] = &ipState{Addr: cand.Addr, Status: IPQueued, Depth: ds.MinDepth, Owner: ref}
			chosen = append(chosen, cand.Addr)
		}
		if len(chosen) == 0 {
			if ds.Attempted > 0 {
				continue // exhausted addresses; a new run has a fresh retry budget
			}
			ds.Status = DevUnscanned
			if !ds.MissingAddressReported {
				ds.MissingAddressReported = true
				c.counts.DevicesUnscanned++
				c.status = "partial"
				c.issues = append(c.issues, model.Issue{Code: "NO_MGMT_ADDRESS", Component: "discovery",
					Message: fmt.Sprintf("device %d has no usable management address", ref)})
			}
			continue
		}
		ds.Enqueued = true
		ds.Status = DevQueued
		out = append(out, DeviceTask{Device: ref, Depth: ds.MinDepth, Candidates: chosen})
		c.emitForDevice(ref, "queued", "", "", chosen[0], "verify")
	}
	return out
}

func (c *Coordinator) addCandidate(ref model.DevRef, a netip.Addr, source string, verified bool) {
	a = a.Unmap()
	if !c.validHostAddr(a) {
		c.terminate(a, "ADDRESS_INVALID", "candidate is not a valid management host address")
		return
	}
	if !c.inScope(a) {
		c.terminate(a, "ADDRESS_OUT_OF_SCOPE", "candidate outside management_cidrs")
		return
	}
	ds := c.devState(ref)
	if ds == nil {
		return
	}
	if ds.Addrs[a] {
		if verified {
			for i := range ds.Candidates {
				if ds.Candidates[i].Addr == a {
					ds.Candidates[i].Verified = true
				}
			}
		}
		return
	}
	ds.Addrs[a] = true
	ds.Candidates = append(ds.Candidates, candidateAddr{
		Addr: a, Source: source, Verified: verified, CIDRIndex: c.cidrIndex(a),
	})
	if source == "manual" {
		ds.Candidates[len(ds.Candidates)-1].ManualPriority = -1
	}
}

func (c *Coordinator) resolveRemotePort(remote model.DevRef, n model.LLDPNeighbor) (model.PortRef, bool) {
	res := c.opts.Resolver.ResolveRemotePort(remote, n, nil, nil)
	c.issues = append(c.issues, res.Issues...)
	if res.Port != nil {
		return res.Port.Ref, true
	}
	return 0, false
}

func (c *Coordinator) recordCandidate(observer model.DevRef, n model.LLDPNeighbor, class identity.Classification, disposition string, at time.Time) {
	c.candidates = append(c.candidates, Candidate{
		Observer: observer, Chassis: n.Chassis, Port: n.Port, SysName: n.SysName,
		Classification: class, Row: n.Index, Disposition: disposition,
		Raw: n, At: at,
	})
}

func (c *Coordinator) devState(ref model.DevRef) *deviceState {
	if ds, ok := c.devStates[ref]; ok {
		return ds
	}
	if len(c.devStates) >= c.opts.MaxDevices {
		c.terminate(netip.Addr{}, "DEVICE_LIMIT", fmt.Sprintf("max_devices %d reached", c.opts.MaxDevices))
		return nil
	}
	ds := &deviceState{Ref: ref, Status: DevUnscanned, MinDepth: 1 << 30, Addrs: map[netip.Addr]bool{}}
	c.devStates[ref] = ds
	c.counts.DevicesDiscovered++
	return ds
}

func (c *Coordinator) markAttempts(r taskResult) {
	for _, a := range r.Task.Candidates {
		st := c.ipStates[a]
		if st == nil {
			continue
		}
		tried := false
		for _, t := range r.Tried {
			if t == a {
				tried = true
				break
			}
		}
		switch {
		case !tried:
			st.Status = IPQueued
		case r.Snapshot != nil && a == r.Addr:
			st.Status = IPSucceeded
		default:
			st.Status = IPFailed
		}
	}
}

func (c *Coordinator) reserveTarget(a netip.Addr) bool {
	if !c.budget.reserve(a) {
		c.status = "partial"
		return false
	}
	c.targets = len(c.budget.addresses)
	c.counts.AdmittedCandidates = c.targets
	return true
}

func (c *Coordinator) inScope(a netip.Addr) bool {
	for _, p := range c.opts.ExcludedCIDRs {
		if p.Contains(a) {
			return false
		}
	}
	for _, p := range c.opts.ManagementCIDRs {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (c *Coordinator) cidrIndex(a netip.Addr) int {
	for i, p := range c.opts.ManagementCIDRs {
		if p.Contains(a) {
			return i
		}
	}
	return len(c.opts.ManagementCIDRs)
}

func (c *Coordinator) ipKnown(a netip.Addr) bool {
	_, ok := c.ipStates[a]
	return ok
}

func (c *Coordinator) terminate(addr netip.Addr, code, msg string) {
	c.status = "partial"
	c.counts.TruncatedBranches++
	switch code {
	case "DEVICE_LIMIT", "TARGET_LIMIT", "DEPTH_LIMIT":
		c.budgetExhausted = true
	}
	c.issues = append(c.issues, model.Issue{Code: code, Component: "discovery", Message: msg})
}

func (c *Coordinator) recordUnresolved(observer model.DevRef, local model.PortRef, remote model.DevRef, n model.LLDPNeighbor, at time.Time, reason string) {
	c.counts.UnresolvedObservations++
	var codes []string
	if p, ok := c.opts.Resolver.Ports().ByRef(local); !ok || !p.Physical || p.Resolution == topology.PortConflict {
		code := "LOCAL_PORT_UNMAPPED"
		if ok && p.Resolution == topology.PortConflict {
			code = "IFINDEX_ALIAS_CONFLICT"
		}
		codes = append(codes, code)
		reason += fmt.Sprintf("; local port ref=%d, LLDP localPortNum=%d", local, n.Index.LocalPortNum)
	}
	if remote != 0 {
		p, ok := c.opts.Resolver.Ports().Get(remote, topology.MakePortKey(n.Port.Subtype, n.Port.Raw))
		if !ok || !p.Physical || p.Resolution == topology.PortConflict {
			code, detail := c.opts.Resolver.RemotePortFailure(remote, n.Port)
			codes = append(codes, code)
			reason += "; " + detail
		}
	}
	c.unresolved = append(c.unresolved, topology.UnresolvedObservation{
		Observer: observer, LocalPort: local, Remote: remote,
		Row: n.Index, Raw: n, Reason: reason, ReasonCodes: codes, At: at,
	})
}

func (c *Coordinator) finalize() *Result {
	wasAborted := c.status == "aborted"
	for _, o := range c.outcomes {
		if d, ok := c.opts.Registry.ByRef(o.Device); ok && d.State == identity.StateConflict {
			c.disableAbsence(o.Device)
		}
	}
	// Resolve evidence only after all layers have registered current local
	// ports. A provisional name alone never proves a physical interface.
	c.links = topology.NewLinkBuilder()
	valid := make([]model.LinkObservation, 0, len(c.observations))
	for _, obs := range c.observations {
		if resolved := c.opts.Resolver.ResolveRemotePort(obs.Remote, obs.Raw, nil, nil); resolved.Port != nil && resolved.Port.Physical {
			obs.RemotePort = resolved.Port.Ref
		}
		a, oka := c.opts.Registry.ByRef(obs.Observer)
		b, okb := c.opts.Registry.ByRef(obs.Remote)
		pa, okpa := c.opts.Resolver.Ports().ByRef(obs.LocalPort)
		pb, okpb := c.opts.Resolver.Ports().ByRef(obs.RemotePort)
		if !oka || !okb || !a.Classification.Managed() || !b.Classification.Managed() ||
			a.State == identity.StateConflict || b.State == identity.StateConflict ||
			!okpa || !okpb || !pa.Physical || !pb.Physical ||
			pa.Resolution == topology.PortConflict || pb.Resolution == topology.PortConflict {
			reason := "endpoint identity, classification or physical port unverified"
			if (oka && a.State == identity.StateConflict) || (okb && b.State == identity.StateConflict) {
				reason = "identity conflict at link endpoint"
			}
			c.recordUnresolved(obs.Observer, obs.LocalPort, obs.Remote, obs.Raw, obs.At, reason)
			c.disableAbsence(obs.Observer)
			c.disableAbsence(obs.Remote)
			c.status = "partial"
			continue
		}
		valid = append(valid, obs)
		c.links.Add(obs)
	}
	c.observations = valid
	lr := c.links.Build()
	c.issues = append(c.issues, lr.Issues...)
	for _, conflict := range lr.Conflicts {
		c.status = "partial"
		c.disableAbsence(conflict.Device)
		for _, peer := range conflict.Remotes {
			c.disableAbsence(peer.Device)
		}
	}
	validKeys := map[model.LinkKey]bool{}
	for _, l := range lr.Links {
		validKeys[l.Key] = true
	}
	retained := c.observations[:0]
	for _, obs := range c.observations {
		key, err := topology.Canonical(obs.Observer, obs.LocalPort, obs.Remote, obs.RemotePort)
		if err != nil || !validKeys[key] {
			c.recordUnresolved(obs.Observer, obs.LocalPort, obs.Remote, obs.Raw, obs.At, "TOPOLOGY_CONFLICT")
			c.disableAbsence(obs.Observer)
			c.disableAbsence(obs.Remote)
			c.status = "partial"
			continue
		}
		retained = append(retained, obs)
	}
	c.observations = retained
	if wasAborted {
		c.status = "aborted"
	}
	switch {
	case c.status == "aborted":
		// aborted is terminal; never downgraded here.
	case c.timedOut:
		c.status = "partial"
	case c.counts.DevicesCollected == 0:
		// No device could be collected: no usable result.
		c.status = "failed"
	case c.status == "":
		c.status = "completed"
	}
	sort.Slice(c.observations, func(i, j int) bool { return lessObservation(c.observations[i], c.observations[j]) })
	sort.Slice(c.unresolved, func(i, j int) bool { return lessUnresolved(c.unresolved[i], c.unresolved[j]) })

	c.counts.LinksObserved = len(lr.Links)
	c.counts.DevicesDiscovered = len(c.formalDevices())
	eligible := map[model.DevRef]bool{}
	for _, o := range c.outcomes {
		value := o.Snapshot != nil && o.Snapshot.AbsenceEligible
		if prior, ok := eligible[o.Device]; ok {
			value = value && prior
		}
		eligible[o.Device] = value
	}
	for _, value := range eligible {
		if value {
			c.counts.EligibleDevices++
		}
	}
	sort.Slice(c.candidates, func(i, j int) bool { return lessCandidate(c.candidates[i], c.candidates[j]) })
	termination := "frontier_empty"
	switch {
	case c.status == "aborted":
		termination = "canceled"
	case c.status == "failed":
		termination = "no_results"
	case c.budgetExhausted:
		termination = "budget_exhausted"
	case c.status == "partial":
		termination = "errors_retained"
	}
	known := map[string]uint64{}
	for _, d := range c.formalDevices() {
		known[d.StrongKey] = uint64(d.Ref)
		for _, k := range d.IdentityKeys {
			known[k] = uint64(d.Ref)
		}
		if k, ok := identity.NormalizedKey(d.Chassis, false); ok {
			known[k] = uint64(d.Ref)
		}
	}
	verifications := c.finishVerifications()
	pendingNodes, pendingLinks := topology.PendingProjection(c.unresolved, known)
	for i := range pendingNodes {
		for _, v := range verifications {
			if topology.CandidateKey(v.Neighbor, uint64(v.SourceDevice)) == pendingNodes[i].Key {
				pendingNodes[i].Verification = v.Details
				pendingNodes[i].ManagementAddresses = v.Neighbor.MgmtAddresses
			}
		}
	}
	c.associateProbeRecords()
	// Retain failures and unscanned admitted devices as first-class scan outcomes.
	// Historical inventory is never turned into a new scan target here.
	seenOutcomes := map[model.DevRef]bool{}
	for _, o := range c.outcomes {
		seenOutcomes[o.Device] = true
	}
	for _, dev := range c.formalDevices() {
		if seenOutcomes[dev.Ref] {
			continue
		}
		ds := c.devStates[dev.Ref]
		if ds == nil {
			continue
		}
		outcome, code := "unscanned", ds.FailureCode
		if ds.Attempted > 0 || ds.Status == DevFailed {
			outcome = "failed"
		}
		if code == "" {
			code = "NOT_SCANNED_THIS_RUN"
		}
		c.outcomes = append(c.outcomes, model.ScanOutcome{Device: dev.Ref, Outcome: outcome,
			Target: model.DiscoveryTarget{Address: ds.SelectedIP, Depth: ds.MinDepth},
			Issues: []model.Issue{{Code: code, Component: "discovery"}}})
	}
	targets := []CollectionTarget{}
	for _, state := range c.ipStates {
		if state.Status == IPSucceeded {
			continue
		}
		status, code := "unscanned", "NOT_SCANNED_THIS_RUN"
		if state.Status == IPFailed {
			status, code = "failed", "COLLECTION_FAILED"
		}
		if ds := c.devStates[state.Owner]; ds != nil && ds.FailureCode != "" {
			code = ds.FailureCode
		}
		targets = append(targets, CollectionTarget{Device: state.Owner, Address: state.Addr.String(), Status: status, ReasonCode: code})
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].Address < targets[j].Address })
	return &Result{
		CollectionTargets: targets,
		Preprobe:          c.probeBatch,
		Verifications:     verifications,
		PendingNodes:      pendingNodes, PendingLinks: pendingLinks,
		SchemaVersion: model.SchemaVersion,
		Status:        c.status,
		Devices:       c.formalDevices(),
		Ports:         c.opts.Resolver.Ports().All(),
		Outcomes:      c.outcomes,
		Observations:  c.observations,
		Unresolved:    c.unresolved,
		Candidates:    c.candidates,
		Links:         lr.Links,
		Counts:        c.counts,
		Issues:        c.issues,
		Termination:   termination,
	}
}

func (c *Coordinator) disableAbsence(ref model.DevRef) {
	for i := range c.outcomes {
		if c.outcomes[i].Device == ref && c.outcomes[i].Snapshot != nil {
			// Do not mutate snapshots supplied by workers or replay fixtures.
			copy := *c.outcomes[i].Snapshot
			copy.AbsenceEligible = false
			c.outcomes[i].Snapshot = &copy
		}
	}
}

// formalDevices keeps only confirmed switches in the formal topology.
func (c *Coordinator) formalDevices() []*identity.Device {
	var out []*identity.Device
	for _, d := range c.opts.Registry.Devices() {
		if d.StrongKey != "" && d.Classification.Managed() && (c.devStates[d.Ref] != nil || d.State == identity.StateConflict) {
			out = append(out, d)
		}
	}
	return out
}

func lessCandidate(a, b Candidate) bool {
	if a.Observer != b.Observer {
		return a.Observer < b.Observer
	}
	if a.Row.TimeMark != b.Row.TimeMark {
		return a.Row.TimeMark < b.Row.TimeMark
	}
	if a.Row.LocalPortNum != b.Row.LocalPortNum {
		return a.Row.LocalPortNum < b.Row.LocalPortNum
	}
	return a.Row.RemoteIndex < b.Row.RemoteIndex
}

func sortCandidates(cands []candidateAddr) {
	sort.SliceStable(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		if a.ManualPriority != b.ManualPriority {
			return a.ManualPriority < b.ManualPriority
		}
		if a.Verified != b.Verified {
			return a.Verified
		}
		if !a.Freshness.Equal(b.Freshness) {
			return a.Freshness.After(b.Freshness)
		}
		if a.CIDRIndex != b.CIDRIndex {
			return a.CIDRIndex < b.CIDRIndex
		}
		if a.Addr.Is4() != b.Addr.Is4() {
			return a.Addr.Is4()
		}
		return a.Addr.Less(b.Addr)
	})
}

func validHostAddr(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	a = a.Unmap()
	if a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	if a.Is4() {
		b := a.As4()
		if b == [4]byte{255, 255, 255, 255} {
			return false
		}
	}
	return true
}

func (c *Coordinator) validHostAddr(a netip.Addr) bool {
	a = a.Unmap()
	if c.opts.AllowIPv4LinkLocal && a.Is4() && a.IsLinkLocalUnicast() {
		return true
	}
	return validHostAddr(a)
}

func lessTaskResult(a, b taskResult) bool {
	if a.Task.Device != b.Task.Device {
		return a.Task.Device < b.Task.Device
	}
	if len(a.Task.Candidates) == 0 || len(b.Task.Candidates) == 0 {
		return len(a.Task.Candidates) < len(b.Task.Candidates)
	}
	return a.Task.Candidates[0].Less(b.Task.Candidates[0])
}

func issueFromErr(component string, err error) model.Issue {
	var transport *snmp.Error
	if errors.As(err, &transport) {
		return model.Issue{Code: string(transport.Code), Component: component, Message: err.Error(), Retryable: transport.Code == snmp.CodeTimeout}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return model.Issue{Code: "SNMP_TIMEOUT", Component: component, Message: err.Error(), Retryable: true}
	}
	return model.Issue{Code: "COLLECT_FAILED", Component: component, Message: err.Error()}
}

func lessObservation(a, b model.LinkObservation) bool {
	if a.Observer != b.Observer {
		return a.Observer < b.Observer
	}
	if a.LocalPort != b.LocalPort {
		return a.LocalPort < b.LocalPort
	}
	if a.Remote != b.Remote {
		return a.Remote < b.Remote
	}
	if a.Row.TimeMark != b.Row.TimeMark {
		return a.Row.TimeMark < b.Row.TimeMark
	}
	if a.Row.LocalPortNum != b.Row.LocalPortNum {
		return a.Row.LocalPortNum < b.Row.LocalPortNum
	}
	return a.Row.RemoteIndex < b.Row.RemoteIndex
}

func lessUnresolved(a, b topology.UnresolvedObservation) bool {
	if a.Observer != b.Observer {
		return a.Observer < b.Observer
	}
	if a.LocalPort != b.LocalPort {
		return a.LocalPort < b.LocalPort
	}
	if a.Row.TimeMark != b.Row.TimeMark {
		return a.Row.TimeMark < b.Row.TimeMark
	}
	if a.Row.LocalPortNum != b.Row.LocalPortNum {
		return a.Row.LocalPortNum < b.Row.LocalPortNum
	}
	return a.Row.RemoteIndex < b.Row.RemoteIndex
}
