package webui

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"gonet/internal/control"
	"gonet/internal/store/postgres"
)

type currentEvidenceBackend struct {
	countingBackend
	evidenceReads int
}

func (b *currentEvidenceBackend) ReadTopologyEvidence(context.Context) (*control.View, error) {
	b.evidenceReads++
	return b.view, nil
}

func TestStateReadsEvidenceOnceAndProjectsCurrentGraph(t *testing.T) {
	v := peerLAGView()
	now := time.Now()
	v.LatestScanFinishedAt = &now
	old := v.LatestScanID - 1
	v.Links = append(v.Links, postgres.ExportLink{ID: 2308, DeviceAID: 1, DeviceBID: 74, DiscoveryState: "active", LastSeenScanID: &old})
	for _, status := range []string{"running", "failed", "aborted"} {
		t.Run(status, func(t *testing.T) {
			v.Evidence.LatestScan = &postgres.ScanState{ID: v.LatestScanID + 1, Status: status}
			b := &currentEvidenceBackend{countingBackend: countingBackend{view: v}}
			s := newTestServer(t, b)
			defer s.Close()
			cookie, _ := testSession(t, s)
			response := callAuth(s.Handler(testHost), "GET", "/api/state", "", cookie, nil)
			if response.Code != 200 {
				t.Fatal(response.Code)
			}
			var result struct {
				Topology struct {
					Links []postgres.ExportLink `json:"links"`
					Graph currentTopologyGraph  `json:"graph"`
				} `json:"topology"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			g := result.Topology.Graph
			if b.reads.Load() != 0 || b.evidenceReads != 1 {
				t.Fatalf("read calls base=%d evidence=%d", b.reads.Load(), b.evidenceReads)
			}
			if len(result.Topology.Links) != len(v.Links) || len(g.Links) != len(v.Links)-1 || g.LatestAttempt.Status != status || g.SnapshotID != v.LatestScanID {
				t.Fatalf("current/history/attempt mixed: %+v", g)
			}
			members := map[string]bool{}
			for _, l := range g.Links {
				members[idString(l.ID)] = true
				if l.ID == 2308 {
					t.Fatal("historical link visible")
				}
			}
			if len(g.AggregateConnections) == 0 {
				t.Fatal("state lost real LAG evidence")
			}
			for _, a := range g.AggregateConnections {
				for _, id := range a.MemberLinkIDs {
					if !members[id] {
						t.Fatalf("aggregate references invisible member %s", id)
					}
				}
			}
		})
	}
}
