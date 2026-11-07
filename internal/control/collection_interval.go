package control

import (
	"fmt"
	"time"
)

// CollectionInterval keeps the operator's chosen unit as well as the value.
// Omitted settings from older clients leave the configured interval intact.
type CollectionInterval struct {
	Value int64  `json:"value"`
	Unit  string `json:"unit"`
}

func (i CollectionInterval) Duration() (time.Duration, error) {
	var unit time.Duration
	switch i.Unit {
	case "minute":
		unit = time.Minute
	case "hour":
		unit = time.Hour
	case "day":
		unit = 24 * time.Hour
	default:
		return 0, fmt.Errorf("采集频率单位必须为分、时或日")
	}
	const maximum = time.Duration(1<<63-1) / 3
	if i.Value < 1 || i.Value > int64(maximum/unit) {
		return 0, fmt.Errorf("采集频率必须为正整数，且不能超出支持的时长")
	}
	return time.Duration(i.Value) * unit, nil
}
func SyncCollectionInterval(s *Settings, interval time.Duration) {
	if s.CollectionInterval != nil {
		if d, err := s.CollectionInterval.Duration(); err == nil && d == interval {
			return
		}
	}
	if interval < time.Minute || interval%time.Minute != 0 {
		s.CollectionInterval = nil
		return
	}
	value := &CollectionInterval{Value: int64(interval / time.Minute), Unit: "minute"}
	if interval%(24*time.Hour) == 0 {
		value.Value = int64(interval / (24 * time.Hour))
		value.Unit = "day"
	} else if interval%time.Hour == 0 {
		value.Value = int64(interval / time.Hour)
		value.Unit = "hour"
	}
	// Preserve legacy sub-minute configuration without converting it to zero.
	s.CollectionInterval = value
}

// TopologyDuration accepts zero as an explicit disabled schedule.
func (i CollectionInterval) TopologyDuration() (time.Duration, error) {
	if i.Value == 0 {
		positive := i
		positive.Value = 1
		_, err := positive.Duration()
		return 0, err
	}
	return i.Duration()
}
func SyncTopologyScanInterval(s *Settings, interval time.Duration) {
	if s.TopologyScanInterval != nil {
		if d, e := s.TopologyScanInterval.TopologyDuration(); e == nil && d == interval {
			return
		}
	}
	if interval == 0 {
		s.TopologyScanInterval = &CollectionInterval{Value: 0, Unit: "minute"}
		return
	}
	copy := Settings{}
	SyncCollectionInterval(&copy, interval)
	s.TopologyScanInterval = copy.CollectionInterval
}
