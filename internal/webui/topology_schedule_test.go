package webui

import (
	"context"
	"gonet/internal/control"
	"testing"
	"time"
)

type scheduledTestBackend struct {
	fakeBackend
	calls chan bool
}

func (b *scheduledTestBackend) Scan(ctx context.Context, supplement bool, p func(Progress)) (RunResult, error) {
	p(Progress{Stage: "scanning"})
	b.calls <- supplement
	<-ctx.Done()
	return RunResult{ScanID: 123, Status: "aborted"}, nil
}
func waitSchedule(t *testing.T, check func() bool) {
	t.Helper()
	end := time.Now().Add(time.Second)
	for !check() {
		if time.Now().After(end) {
			t.Fatal("scheduler did not update")
		}
		time.Sleep(time.Millisecond)
	}
}
func TestTopologyScheduleUsesSharedJobAndDisablesAtZero(t *testing.T) {
	b := &scheduledTestBackend{calls: make(chan bool, 4)}
	s := newTestServer(t, b)
	defer s.Close()
	base := time.Now().Add(time.Hour)
	if d := s.topologyScheduleStep(base); d != 0 {
		t.Fatal("schedule enabled by default")
	}
	settings := control.Settings{TopologyScanInterval: &control.CollectionInterval{Value: 1, Unit: "minute"}}
	b.SaveSettings(settings)
	if d := s.topologyScheduleStep(base); d != time.Minute {
		t.Fatal("wrong first due time", d)
	}
	s.topologyScheduleStep(base.Add(time.Minute))
	select {
	case supplement := <-b.calls:
		if supplement {
			t.Fatal("automatic scan enabled supplementation")
		}
	case <-time.After(time.Second):
		t.Fatal("automatic scan did not call common backend")
	}
	s.mu.Lock()
	if !s.job.Running || s.job.Progress.Stage != "scanning" || s.cancel == nil {
		t.Fatal("automatic scan bypassed job/progress/cancel")
	}
	s.mu.Unlock()
	s.topologyScheduleStep(base.Add(2 * time.Minute))
	select {
	case <-b.calls:
		t.Fatal("overlapping automatic scan queued")
	default:
	}
	s.mu.Lock()
	if _, err := s.startScanLocked(false); err == nil {
		t.Fatal("manual scan overlapped automatic scan")
	}
	s.cancel()
	s.mu.Unlock()
	waitSchedule(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return !s.job.Running })
	settings.TopologyScanInterval = &control.CollectionInterval{Value: 0, Unit: "day"}
	b.SaveSettings(settings)
	if d := s.topologyScheduleStep(base.Add(3 * time.Minute)); d != 0 {
		t.Fatal("zero did not disable")
	}
	s.topologyScheduleStep(base.Add(100 * time.Hour))
	select {
	case <-b.calls:
		t.Fatal("disabled schedule still ran")
	default:
	}
	s.mu.Lock()
	_, err := s.startScanLocked(false)
	s.mu.Unlock()
	if err != nil {
		t.Fatal("manual update unavailable while disabled", err)
	}
	select {
	case <-b.calls:
	case <-time.After(time.Second):
		t.Fatal("manual update failed")
	}
}
func TestTopologyScheduleHotReloadAndShutdown(t *testing.T) {
	b := &scheduledTestBackend{calls: make(chan bool, 1)}
	s := newTestServer(t, b)
	set := func(value int64, unit string) {
		b.SaveSettings(control.Settings{TopologyScanInterval: &control.CollectionInterval{Value: value, Unit: unit}})
		select {
		case s.topologyChanged <- struct{}{}:
		default:
		}
	}
	set(1, "day")
	waitSchedule(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.topologyInterval == 24*time.Hour && !s.topologyNextAt.IsZero()
	})
	set(1, "minute")
	waitSchedule(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.topologyInterval == time.Minute && time.Until(s.topologyNextAt) <= time.Minute
	})
	set(0, "hour")
	waitSchedule(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.topologyInterval == 0 && s.topologyNextAt.IsZero()
	})
	s.Close()
	if s.ctx.Err() == nil {
		t.Fatal("close did not stop scheduler")
	}
}
