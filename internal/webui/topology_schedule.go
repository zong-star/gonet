package webui

import "time"

// topologyScheduleStep also makes due-time behavior testable without waiting
// a real minute or starting a second discovery implementation.
func (s *Server) topologyScheduleStep(now time.Time) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return 0
	}
	var interval time.Duration
	if setting := s.backend.Settings().TopologyScanInterval; setting != nil {
		d, err := setting.TopologyDuration()
		if err == nil {
			interval = d
		}
	}
	if interval == 0 {
		s.topologyInterval = 0
		s.topologyNextAt = time.Time{}
		return 0
	}
	if interval != s.topologyInterval || s.topologyNextAt.IsZero() {
		s.topologyInterval = interval
		s.topologyNextAt = now.Add(interval)
	}
	if now.Before(s.topologyNextAt) {
		return s.topologyNextAt.Sub(now)
	}
	// Skip an occupied due time; never queue a backlog or overlap a manual job.
	s.topologyNextAt = now.Add(interval)
	if !s.job.Running {
		_, _ = s.startScanLocked(false)
	}
	return interval
}
func (s *Server) runTopologySchedule() {
	defer s.wg.Done()
	for {
		delay := s.topologyScheduleStep(time.Now())
		var timer *time.Timer
		var due <-chan time.Time
		if delay > 0 {
			timer = time.NewTimer(delay)
			due = timer.C
		}
		select {
		case <-s.ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-s.topologyChanged:
			if timer != nil {
				timer.Stop()
			}
		case <-due:
		}
	}
}
